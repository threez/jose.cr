module JOSE
  # JWE (JSON Web Encryption) compact serialization (RFC 7516).
  #
  # The two header parameters that control how a JWE token is produced are
  # defined in RFC 7516 §4.1:
  #
  # **`alg` — Key Management Algorithm** (how the Content Encryption Key is
  # protected):
  # - *Single asymmetric key pair (RSA):* `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`
  # - *Two key pairs with key agreement (ECDH-ES):*
  #   `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`
  # - *Symmetric key wrap (AES-KW):* `A128KW`, `A192KW`, `A256KW`
  # - *Symmetric direct key (pre-shared):* `dir`
  #
  # **`enc` — Content Encryption Algorithm** (authenticated encryption of the
  # plaintext using the CEK):
  # - *AES-GCM:* `A128GCM`, `A192GCM`, `A256GCM`
  # - *AES-CBC + HMAC-SHA2:* `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`
  module JWE
    # Encrypts *plain_text* for *jwk* and returns a compact `EncryptedBinary`.
    #
    # *header_overrides* is an optional map that may contain:
    # - `"alg"` — override the key-wrap algorithm (default is inferred from key
    #   type: EC → `"ECDH-ES+A256KW"`, RSA → `"RSA-OAEP"`, oct 16/24/32 bytes
    #   → `"A128KW"`/`"A192KW"`/`"A256KW"`, other oct → `"dir"`)
    # - `"enc"` — override the content-encryption algorithm (default: `"A256GCM"`)
    # - `"kid"` — included verbatim in the protected header
    # - Any other key — included in the protected header as-is
    #
    # ```
    # jwk = JOSE::JWK.generate_key({"kty" => JSON::Any.new("EC"), "crv" => JSON::Any.new("P-256")})
    # enc = JOSE::JWE.block_encrypt(jwk, "hello world")
    # plain = JOSE::JWE.block_decrypt(jwk, enc)
    # ```
    def self.block_encrypt(jwk : JWK, plain_text : String,
                           header_overrides : Hash(String, JSON::Any)? = nil) : EncryptedBinary
      alg, enc = resolve_alg_enc(jwk, header_overrides)
      zip = header_overrides.try(&.["zip"]?.try(&.as_s))
      cek_len, iv_len = enc_params(enc)

      # ── Generate CEK and encrypted_key ────────────────────────────────────
      cek = Bytes.empty
      encrypted_key = Bytes.empty
      epk_json : Hash(String, JSON::Any)? = nil
      gcmkw : {Bytes, Bytes}? = nil

      case alg
      when "dir"
        cek = jwk.key_bytes
      when "A128KW", "A192KW", "A256KW"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = JWA::AES_KW.wrap(jwk.key_bytes, cek)
      when "A128GCMKW", "A192GCMKW", "A256GCMKW"
        cek = Random::Secure.random_bytes(cek_len)
        kw_iv = Random::Secure.random_bytes(12)
        encrypted_key, kw_tag = JWA::AES_GCM.encrypt(jwk.key_bytes, kw_iv, cek, Bytes.empty)
        gcmkw = {kw_iv, kw_tag}
      when "ECDH-ES"
        # RFC 7518 §4.6.2: for direct key agreement the ConcatKDF algorithm ID
        # is the "enc" value, not the "alg" value.
        cek, epk_json = ecdh_es_derive(jwk, enc, enc, cek_len * 8)
      when "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
        kw_alg = alg[8..] # "A128KW" etc.
        kw_key_len = kw_alg_key_len(kw_alg)
        # RFC 7518 §4.6.2: for key wrapping, the ConcatKDF algorithm ID is the
        # full "alg" value (e.g. "ECDH-ES+A128KW"), not the stripped KW portion.
        derived, epk_json = ecdh_es_derive(jwk, alg, enc, kw_key_len * 8)
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = JWA::AES_KW.wrap(derived, cek)
      when "RSA-OAEP"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :oaep_sha1)
      when "RSA-OAEP-256"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :oaep_sha256)
      when "RSA1_5"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :pkcs1)
      else
        raise ArgumentError.new("Unsupported JWE alg: #{alg}")
      end

      # ── Build protected header ─────────────────────────────────────────────
      kid = jwk["kid"]?.try(&.as_s)
      protected_header = Base64Url.encode(
        String.build { |io|
          JSON.build(io) do |json|
            json.object do
              json.field "alg", alg
              json.field "enc", enc
              json.field "zip", zip if zip
              json.field "kid", kid if kid
              if epk_json
                json.field "epk" do
                  json.object do
                    epk_json.each { |k, v| json.field k, v }
                  end
                end
              end
              if kw = gcmkw
                json.field "iv", Base64Url.encode(kw[0])
                json.field "tag", Base64Url.encode(kw[1])
              end
              header_overrides.try &.each do |k, v|
                next if %w[alg enc zip kid epk iv tag].includes?(k)
                json.field k, v
              end
            end
          end
        }.to_slice
      )

      # ── Encrypt content ────────────────────────────────────────────────────
      iv = Random::Secure.random_bytes(iv_len)
      aad = protected_header.to_slice
      content = zip == "DEF" ? deflate_compress(plain_text.to_slice) : plain_text.to_slice
      ciphertext, tag = enc_encrypt(enc, cek, iv, content, aad)

      compact = String.build do |io|
        io << protected_header
        io << '.'
        io << Base64Url.encode(encrypted_key)
        io << '.'
        io << Base64Url.encode(iv)
        io << '.'
        io << Base64Url.encode(ciphertext)
        io << '.'
        io << Base64Url.encode(tag)
      end

      EncryptedBinary.new(compact)
    end

    # Decrypts a compact JWE using *jwk*, which must contain the private key
    # (or the symmetric key for `"dir"` / AES Key Wrap algorithms).
    #
    # *encrypted* may be either a raw compact serialization `String` or an
    # `EncryptedBinary` returned by `#block_encrypt`. Raises `ArgumentError` if
    # the string does not contain exactly five dot-separated parts.
    def self.block_decrypt(jwk : JWK, encrypted : String | EncryptedBinary) : String
      compact = encrypted.is_a?(EncryptedBinary) ? encrypted.compact : encrypted
      parts = compact.split('.')
      raise ArgumentError.new("Invalid compact JWE") unless parts.size == 5

      protected_header_b64 = parts[0]
      encrypted_key_bytes = Base64Url.decode(parts[1])
      iv = Base64Url.decode(parts[2])
      ciphertext = Base64Url.decode(parts[3])
      tag = Base64Url.decode(parts[4])

      header = JSON.parse(String.new(Base64Url.decode(protected_header_b64))).as_h
      alg = header["alg"].as_s
      enc = header["enc"].as_s
      aad = protected_header_b64.to_slice

      # ── Unwrap CEK and decrypt ────────────────────────────────────────────
      cek_len, _ = enc_params(enc)
      cek = unwrap_cek(jwk, alg, enc, header, encrypted_key_bytes, cek_len)
      plaintext = enc_decrypt(enc, cek, iv, ciphertext, tag, aad)
      plaintext = deflate_decompress(plaintext) if header["zip"]?.try(&.as_s) == "DEF"
      String.new(plaintext)
    end

    # Encrypts *plain_text* for *jwk* and returns a JWE Flattened JSON
    # Serialization string (RFC 7516 §7.2.2).
    #
    # All key-management parameters go into the protected header.  An optional
    # *aad* byte slice is base64url-encoded and stored as the `"aad"` member;
    # it is also included in the AEAD computation.
    def self.json_encrypt(jwk : JWK, plain_text : String,
                          header_overrides : Hash(String, JSON::Any)? = nil,
                          aad : Bytes? = nil) : String
      alg, enc = resolve_alg_enc(jwk, header_overrides)
      zip = header_overrides.try(&.["zip"]?.try(&.as_s))
      cek_len, iv_len = enc_params(enc)

      cek = Bytes.empty
      encrypted_key = Bytes.empty
      epk_json : Hash(String, JSON::Any)? = nil
      gcmkw : {Bytes, Bytes}? = nil

      case alg
      when "dir"
        cek = jwk.key_bytes
      when "A128KW", "A192KW", "A256KW"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = JWA::AES_KW.wrap(jwk.key_bytes, cek)
      when "A128GCMKW", "A192GCMKW", "A256GCMKW"
        cek = Random::Secure.random_bytes(cek_len)
        kw_iv = Random::Secure.random_bytes(12)
        encrypted_key, kw_tag = JWA::AES_GCM.encrypt(jwk.key_bytes, kw_iv, cek, Bytes.empty)
        gcmkw = {kw_iv, kw_tag}
      when "ECDH-ES"
        cek, epk_json = ecdh_es_derive(jwk, enc, enc, cek_len * 8)
      when "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
        kw_alg = alg[8..]
        kw_key_len = kw_alg_key_len(kw_alg)
        derived, epk_json = ecdh_es_derive(jwk, alg, enc, kw_key_len * 8)
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = JWA::AES_KW.wrap(derived, cek)
      when "RSA-OAEP"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :oaep_sha1)
      when "RSA-OAEP-256"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :oaep_sha256)
      when "RSA1_5"
        cek = Random::Secure.random_bytes(cek_len)
        encrypted_key = rsa_encrypt(jwk, cek, :pkcs1)
      else
        raise ArgumentError.new("Unsupported JWE alg: #{alg}")
      end

      kid = jwk["kid"]?.try(&.as_s)
      protected_b64 = Base64Url.encode(
        String.build { |io|
          JSON.build(io) do |json|
            json.object do
              json.field "alg", alg
              json.field "enc", enc
              json.field "zip", zip if zip
              json.field "kid", kid if kid
              if epk_json
                json.field "epk" do
                  json.object { epk_json.each { |k, v| json.field k, v } }
                end
              end
              if kw = gcmkw
                json.field "iv", Base64Url.encode(kw[0])
                json.field "tag", Base64Url.encode(kw[1])
              end
              header_overrides.try &.each do |k, v|
                next if %w[alg enc zip kid epk iv tag].includes?(k)
                json.field k, v
              end
            end
          end
        }.to_slice
      )

      aad_b64 = aad.try { |bytes| Base64Url.encode(bytes) }
      content_aad = aad_b64 ? "#{protected_b64}.#{aad_b64}".to_slice : protected_b64.to_slice
      content = zip == "DEF" ? deflate_compress(plain_text.to_slice) : plain_text.to_slice
      iv = Random::Secure.random_bytes(iv_len)
      ciphertext, tag = enc_encrypt(enc, cek, iv, content, content_aad)

      String.build do |io|
        JSON.build(io) do |json|
          json.object do
            json.field "protected", protected_b64
            json.field "encrypted_key", Base64Url.encode(encrypted_key)
            json.field "aad", aad_b64 if aad_b64
            json.field "iv", Base64Url.encode(iv)
            json.field "ciphertext", Base64Url.encode(ciphertext)
            json.field "tag", Base64Url.encode(tag)
          end
        end
      end
    end

    # Decrypts a JWE JSON Serialization (RFC 7516 §7.2), either the Flattened
    # or General form.  For the general form with multiple recipients, iterates
    # until a recipient whose `encrypted_key` can be unwrapped with *jwk* is
    # found.  Raises `ArgumentError` if no matching recipient exists.
    def self.json_decrypt(jwk : JWK, json : String) : String
      parsed = JSON.parse(json).as_h
      protected_b64 = parsed["protected"]?.try(&.as_s) || ""
      unprotected_h = parsed["unprotected"]?.try(&.as_h)
      iv = Base64Url.decode(parsed["iv"].as_s)
      ciphertext = Base64Url.decode(parsed["ciphertext"].as_s)
      tag = Base64Url.decode(parsed["tag"].as_s)

      # RFC 7516 §5.2 step 13 — build AEAD AAD
      aad = if aad_b64 = parsed["aad"]?.try(&.as_s)
              "#{protected_b64}.#{aad_b64}".to_slice
            else
              protected_b64.to_slice
            end

      protected_h = protected_b64.empty? ? {} of String => JSON::Any : JSON.parse(String.new(Base64Url.decode(protected_b64))).as_h

      # General form has a "recipients" array; flattened form is a single entry.
      entries = parsed["recipients"]?.try { |arr| arr.as_a.map(&.as_h) } || [parsed]

      entries.each do |entry|
        per_h = entry["header"]?.try(&.as_h)
        ek_b64 = entry["encrypted_key"]?.try(&.as_s) || ""
        ek = ek_b64.empty? ? Bytes.empty : Base64Url.decode(ek_b64)

        # Merge headers — ascending precedence: per-recipient < unprotected < protected
        merged = {} of String => JSON::Any
        per_h.try { |hdr| hdr.each { |key, val| merged[key] = val } }
        unprotected_h.try { |hdr| hdr.each { |key, val| merged[key] = val } }
        protected_h.each { |key, val| merged[key] = val }

        alg = merged["alg"]?.try(&.as_s)
        enc = merged["enc"]?.try(&.as_s)
        next unless alg && enc

        cek_len, _ = enc_params(enc)
        cek = begin
          unwrap_cek(jwk, alg, enc, merged, ek, cek_len)
        rescue
          next
        end

        plaintext = enc_decrypt(enc, cek, iv, ciphertext, tag, aad)
        plaintext = deflate_decompress(plaintext) if merged["zip"]?.try(&.as_s) == "DEF"
        return String.new(plaintext)
      end

      raise ArgumentError.new("No matching recipient in JWE JSON")
    end

    # Encrypts *plain_text* using a PBES2 password-based key-wrap algorithm.
    #
    # *header_overrides* may include:
    # - `"alg"` — PBES2 variant; default is `"PBES2-HS512+A256KW"`
    # - `"enc"` — content-encryption algorithm; default is `"A256GCM"`
    # - `"p2c"` — PBKDF2 iteration count (integer); default is `310000`
    # - Any other key — included verbatim in the protected header
    #
    # A random 16-byte salt input (`p2s`) is always generated and stored in
    # the protected header alongside `p2c`.
    def self.block_encrypt(password : String, plain_text : String,
                           header_overrides : Hash(String, JSON::Any)? = nil) : EncryptedBinary
      alg = header_overrides.try(&.["alg"]?.try(&.as_s)) || "PBES2-HS512+A256KW"
      enc = header_overrides.try(&.["enc"]?.try(&.as_s)) || "A256GCM"
      p2c = header_overrides.try(&.["p2c"]?.try(&.as_i)) || 310_000
      cek_len, iv_len = enc_params(enc)

      unless alg.starts_with?("PBES2-")
        raise ArgumentError.new("block_encrypt(password) requires a PBES2 alg, got: #{alg}")
      end

      p2s = Random::Secure.random_bytes(16)
      kek = JWA::PBES2.derive_key(password.to_slice, alg, p2s, p2c)
      cek = Random::Secure.random_bytes(cek_len)
      encrypted_key = JWA::AES_KW.wrap(kek, cek)

      protected_header = Base64Url.encode(
        String.build { |io|
          JSON.build(io) do |json|
            json.object do
              json.field "alg", alg
              json.field "enc", enc
              json.field "p2s", Base64Url.encode(p2s)
              json.field "p2c", p2c
              header_overrides.try &.each do |k, v|
                next if %w[alg enc p2s p2c].includes?(k)
                json.field k, v
              end
            end
          end
        }.to_slice
      )

      iv = Random::Secure.random_bytes(iv_len)
      aad = protected_header.to_slice
      ciphertext, tag = enc_encrypt(enc, cek, iv, plain_text.to_slice, aad)

      compact = String.build do |io|
        io << protected_header
        io << '.'
        io << Base64Url.encode(encrypted_key)
        io << '.'
        io << Base64Url.encode(iv)
        io << '.'
        io << Base64Url.encode(ciphertext)
        io << '.'
        io << Base64Url.encode(tag)
      end

      EncryptedBinary.new(compact)
    end

    # Decrypts a compact PBES2 JWE token using the given *password*.
    # Reads `alg`, `p2s`, and `p2c` from the protected header to reconstruct
    # the key-encryption key via PBKDF2, then unwraps the CEK and decrypts.
    def self.block_decrypt(password : String, encrypted : String | EncryptedBinary) : String
      compact = encrypted.is_a?(EncryptedBinary) ? encrypted.compact : encrypted
      parts = compact.split('.')
      raise ArgumentError.new("Invalid compact JWE") unless parts.size == 5

      protected_header_b64 = parts[0]
      encrypted_key_bytes = Base64Url.decode(parts[1])
      iv = Base64Url.decode(parts[2])
      ciphertext = Base64Url.decode(parts[3])
      tag = Base64Url.decode(parts[4])

      header = JSON.parse(String.new(Base64Url.decode(protected_header_b64))).as_h
      alg = header["alg"].as_s
      enc = header["enc"].as_s
      p2s = Base64Url.decode(header["p2s"].as_s)
      p2c = header["p2c"].as_i
      aad = protected_header_b64.to_slice

      unless alg.starts_with?("PBES2-")
        raise ArgumentError.new("block_decrypt(password) requires a PBES2 alg, got: #{alg}")
      end

      kek = JWA::PBES2.derive_key(password.to_slice, alg, p2s, p2c)
      cek = JWA::AES_KW.unwrap(kek, encrypted_key_bytes)

      plaintext = enc_decrypt(enc, cek, iv, ciphertext, tag, aad)
      String.new(plaintext)
    end

    # ── Peek helpers ──────────────────────────────────────────────────────────

    # Returns the decoded protected header from *compact* without decrypting.
    def self.peek_protected(compact : String) : Hash(String, JSON::Any)
      JSON.parse(String.new(Base64Url.decode(compact.split('.').first))).as_h
    end

    # Returns the wrapped CEK bytes from *compact*.
    def self.peek_encrypted_key(compact : String) : Bytes
      Base64Url.decode(compact.split('.')[1])
    end

    # Returns the IV bytes from *compact*.
    def self.peek_iv(compact : String) : Bytes
      Base64Url.decode(compact.split('.')[2])
    end

    # Returns the ciphertext bytes from *compact*.
    def self.peek_ciphertext(compact : String) : Bytes
      Base64Url.decode(compact.split('.')[3])
    end

    # Returns the authentication tag bytes from *compact*.
    def self.peek_tag(compact : String) : Bytes
      Base64Url.decode(compact.split('.')[4])
    end

    # ── Private helpers ───────────────────────────────────────────────────────

    private def self.resolve_alg_enc(jwk : JWK, overrides : Hash(String, JSON::Any)?) : {String, String}
      alg = overrides.try(&.["alg"]?.try(&.as_s))
      enc = overrides.try(&.["enc"]?.try(&.as_s))

      # Default alg based on key type
      unless alg
        alg = case jwk.kty
              when "EC"  then "ECDH-ES+A256KW"
              when "RSA" then "RSA-OAEP"
              when "oct"
                case jwk.key_bytes.size
                when 16 then "A128KW"
                when 24 then "A192KW"
                when 32 then "A256KW"
                else         "dir"
                end
              when "OKP" then raise ArgumentError.new("OKP keys are for JWS only")
              else            raise ArgumentError.new("Cannot infer alg for kty=#{jwk.kty}")
              end
      end

      enc ||= "A256GCM"
      {alg, enc}
    end

    # Returns {cek_len, iv_len} for a given enc algorithm.
    private def self.enc_params(enc : String) : {Int32, Int32}
      case enc
      when "A128GCM"       then {16, 12}
      when "A192GCM"       then {24, 12}
      when "A256GCM"       then {32, 12}
      when "A128CBC-HS256" then {32, 16}
      when "A192CBC-HS384" then {48, 16}
      when "A256CBC-HS512" then {64, 16}
      else                      raise ArgumentError.new("Unsupported JWE enc: #{enc}")
      end
    end

    private def self.kw_alg_key_len(kw_alg : String) : Int32
      case kw_alg
      when "A128KW" then 16
      when "A192KW" then 24
      when "A256KW" then 32
      else               raise ArgumentError.new("Unknown KW alg: #{kw_alg}")
      end
    end

    # Unwraps the Content Encryption Key for a single recipient.
    # *header* is the merged header map that provides algorithm-specific
    # parameters (e.g. `"epk"` for ECDH-ES, `"iv"`/`"tag"` for GCMKW).
    private def self.unwrap_cek(jwk : JWK, alg : String, enc : String,
                                header : Hash(String, JSON::Any),
                                encrypted_key : Bytes, cek_len : Int32) : Bytes
      case alg
      when "dir"
        jwk.key_bytes
      when "A128KW", "A192KW", "A256KW"
        JWA::AES_KW.unwrap(jwk.key_bytes, encrypted_key)
      when "A128GCMKW", "A192GCMKW", "A256GCMKW"
        kw_iv = Base64Url.decode(header["iv"].as_s)
        kw_tag = Base64Url.decode(header["tag"].as_s)
        JWA::AES_GCM.decrypt(jwk.key_bytes, kw_iv, encrypted_key, kw_tag, Bytes.empty)
      when "ECDH-ES"
        ecdh_es_unwrap(jwk, header, enc, enc, cek_len * 8)
      when "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"
        kw_key_len = kw_alg_key_len(alg[8..])
        derived = ecdh_es_unwrap(jwk, header, alg, enc, kw_key_len * 8)
        JWA::AES_KW.unwrap(derived, encrypted_key)
      when "RSA-OAEP"
        rsa_decrypt(jwk, encrypted_key, :oaep_sha1)
      when "RSA-OAEP-256"
        rsa_decrypt(jwk, encrypted_key, :oaep_sha256)
      when "RSA1_5"
        rsa_decrypt(jwk, encrypted_key, :pkcs1)
      else
        raise ArgumentError.new("Unsupported JWE alg: #{alg}")
      end
    end

    # Returns {cek, epk_json_map} for ECDH-ES alg variants (encryption side).
    private def self.ecdh_es_derive(jwk : JWK, alg : String, enc : String,
                                    key_bits : Int32) : {Bytes, Hash(String, JSON::Any)}
      recipient_pub = jwk.ec_public_key
      begin
        crv = jwk["crv"].as_s
        nid = JWA::ECDH_ES.nid_for_crv(crv)
        ephemeral = JWA::ECDH_ES.generate_ephemeral(nid)
        begin
          shared = JWA::ECDH_ES.compute_shared_secret(ephemeral, recipient_pub)
          derived = JWA::ECDH_ES.derive_key(shared, alg, key_bits)

          pub_bytes = JWA::ECDH_ES.public_key_bytes(ephemeral)
          field_size = JWA::ECDH_ES.ec_field_size(ephemeral)
          epk_x = pub_bytes[1, field_size]
          epk_y = pub_bytes[1 + field_size, field_size]

          epk_map = JSON.parse({
            "kty" => "EC",
            "crv" => crv,
            "x"   => Base64Url.encode(epk_x),
            "y"   => Base64Url.encode(epk_y),
          }.to_json).as_h

          {derived, epk_map}
        ensure
          LibCrypto.ec_key_free(ephemeral)
        end
      ensure
        LibCrypto.ec_key_free(recipient_pub)
      end
    end

    # Returns derived key for ECDH-ES (decryption side) using header["epk"].
    private def self.ecdh_es_unwrap(jwk : JWK, header : Hash(String, JSON::Any),
                                    alg : String, enc : String, key_bits : Int32) : Bytes
      epk_map = header["epk"].as_h
      epk_jwk = JWK.from_map(epk_map)
      ephemeral_pub = epk_jwk.ec_public_key
      begin
        recipient_priv = jwk.ec_private_key
        begin
          shared = JWA::ECDH_ES.compute_shared_secret(recipient_priv, ephemeral_pub)
          JWA::ECDH_ES.derive_key(shared, alg, key_bits)
        ensure
          LibCrypto.ec_key_free(recipient_priv)
        end
      ensure
        LibCrypto.ec_key_free(ephemeral_pub)
      end
    end

    private def self.enc_encrypt(enc : String, cek : Bytes, iv : Bytes,
                                 plaintext : Bytes, aad : Bytes) : {Bytes, Bytes}
      case enc
      when "A128GCM", "A192GCM", "A256GCM"
        JWA::AES_GCM.encrypt(cek, iv, plaintext, aad)
      when "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
        JWA::AES_CBC_HMAC.encrypt(cek, iv, plaintext, aad)
      else
        raise ArgumentError.new("Unsupported enc: #{enc}")
      end
    end

    private def self.enc_decrypt(enc : String, cek : Bytes, iv : Bytes,
                                 ciphertext : Bytes, tag : Bytes, aad : Bytes) : Bytes
      case enc
      when "A128GCM", "A192GCM", "A256GCM"
        JWA::AES_GCM.decrypt(cek, iv, ciphertext, tag, aad)
      when "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
        JWA::AES_CBC_HMAC.decrypt(cek, iv, ciphertext, tag, aad)
      else
        raise ArgumentError.new("Unsupported enc: #{enc}")
      end
    end

    private def self.rsa_encrypt(jwk : JWK, plaintext : Bytes, mode : Symbol) : Bytes
      rsa = jwk.rsa_raw_key
      begin
        rsa_size = LibCryptoJose.RSA_size(rsa)
        out_buf = Bytes.new(rsa_size)
        case mode
        when :oaep_sha1
          len = LibCryptoJose.RSA_public_encrypt(plaintext.size, plaintext, out_buf, rsa, LibCryptoJose::RSA_PKCS1_OAEP_PADDING)
          raise "RSA_public_encrypt failed" if len < 0
          out_buf[0, len]
        when :pkcs1
          len = LibCryptoJose.RSA_public_encrypt(plaintext.size, plaintext, out_buf, rsa, LibCryptoJose::RSA_PKCS1_PADDING)
          raise "RSA_public_encrypt failed" if len < 0
          out_buf[0, len]
        when :oaep_sha256
          rsa_oaep256_encrypt(rsa, plaintext)
        else
          raise ArgumentError.new("Unknown RSA mode")
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    private def self.rsa_decrypt(jwk : JWK, ciphertext : Bytes, mode : Symbol) : Bytes
      rsa = jwk.rsa_raw_key
      begin
        rsa_size = LibCryptoJose.RSA_size(rsa)
        out_buf = Bytes.new(rsa_size)
        case mode
        when :oaep_sha1
          len = LibCryptoJose.RSA_private_decrypt(ciphertext.size, ciphertext, out_buf, rsa, LibCryptoJose::RSA_PKCS1_OAEP_PADDING)
          raise "RSA_private_decrypt failed" if len < 0
          out_buf[0, len]
        when :pkcs1
          len = LibCryptoJose.RSA_private_decrypt(ciphertext.size, ciphertext, out_buf, rsa, LibCryptoJose::RSA_PKCS1_PADDING)
          raise "RSA_private_decrypt failed" if len < 0
          out_buf[0, len]
        when :oaep_sha256
          rsa_oaep256_decrypt(rsa, ciphertext)
        else
          raise ArgumentError.new("Unknown RSA mode")
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    private def self.rsa_oaep256_encrypt(rsa : LibCryptoJose::RSA, plaintext : Bytes) : Bytes
      pkey = LibCryptoJose.EVP_PKEY_new
      raise "EVP_PKEY_new failed" if pkey.null?
      begin
        LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
        ctx = LibCryptoJose.EVP_PKEY_CTX_new(pkey, Pointer(Void).null)
        raise "EVP_PKEY_CTX_new failed" if ctx.null?
        begin
          raise "EVP_PKEY_encrypt_init failed" unless LibCryptoJose.EVP_PKEY_encrypt_init(ctx) == 1
          raise "EVP_PKEY_CTX_ctrl failed (padding)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_PADDING, LibCryptoJose::RSA_PKCS1_OAEP_PADDING, Pointer(Void).null) > 0
          raise "EVP_PKEY_CTX_ctrl failed (oaep md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_OAEP_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
          raise "EVP_PKEY_CTX_ctrl failed (mgf1 md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_MGF1_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
          outlen = LibC::SizeT.new(0)
          LibCryptoJose.EVP_PKEY_encrypt(ctx, Pointer(UInt8).null, pointerof(outlen), plaintext, plaintext.size)
          out_buf = Bytes.new(outlen)
          ret = LibCryptoJose.EVP_PKEY_encrypt(ctx, out_buf, pointerof(outlen), plaintext, plaintext.size)
          raise "EVP_PKEY_encrypt failed" unless ret == 1
          out_buf[0, outlen.to_i]
        ensure
          LibCryptoJose.EVP_PKEY_CTX_free(ctx)
        end
      ensure
        LibCryptoJose.EVP_PKEY_free(pkey)
      end
    end

    private def self.rsa_oaep256_decrypt(rsa : LibCryptoJose::RSA, ciphertext : Bytes) : Bytes
      pkey = LibCryptoJose.EVP_PKEY_new
      raise "EVP_PKEY_new failed" if pkey.null?
      begin
        LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
        ctx = LibCryptoJose.EVP_PKEY_CTX_new(pkey, Pointer(Void).null)
        raise "EVP_PKEY_CTX_new failed" if ctx.null?
        begin
          raise "EVP_PKEY_decrypt_init failed" unless LibCryptoJose.EVP_PKEY_decrypt_init(ctx) == 1
          raise "EVP_PKEY_CTX_ctrl failed (padding)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_PADDING, LibCryptoJose::RSA_PKCS1_OAEP_PADDING, Pointer(Void).null) > 0
          raise "EVP_PKEY_CTX_ctrl failed (oaep md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_OAEP_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
          raise "EVP_PKEY_CTX_ctrl failed (mgf1 md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                              LibCryptoJose::EVP_PKEY_CTRL_RSA_MGF1_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
          outlen = LibC::SizeT.new(0)
          LibCryptoJose.EVP_PKEY_decrypt(ctx, Pointer(UInt8).null, pointerof(outlen), ciphertext, ciphertext.size)
          out_buf = Bytes.new(outlen)
          ret = LibCryptoJose.EVP_PKEY_decrypt(ctx, out_buf, pointerof(outlen), ciphertext, ciphertext.size)
          raise "EVP_PKEY_decrypt failed" unless ret == 1
          out_buf[0, outlen.to_i]
        ensure
          LibCryptoJose.EVP_PKEY_CTX_free(ctx)
        end
      ensure
        LibCryptoJose.EVP_PKEY_free(pkey)
      end
    end

    private def self.deflate_compress(data : Bytes) : Bytes
      io = IO::Memory.new
      Compress::Deflate::Writer.open(io, &.write(data))
      io.to_slice
    end

    private def self.deflate_decompress(data : Bytes) : Bytes
      out_io = IO::Memory.new
      Compress::Deflate::Reader.open(IO::Memory.new(data)) { |rdr| IO.copy(rdr, out_io) }
      out_io.to_slice
    end
  end
end
