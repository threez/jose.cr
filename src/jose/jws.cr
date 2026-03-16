module JOSE
  # JWS (JSON Web Signature) compact serialization (RFC 7515).
  #
  # **`alg` — Signature Algorithm:**
  # - *ECDSA (EC keys):* `ES256` (P-256 + SHA-256), `ES384` (P-384 + SHA-384),
  #   `ES512` (P-521 + SHA-512)
  # - *EdDSA (OKP / Ed25519 keys):* `EdDSA`
  # - *HMAC using SHA-2 (oct keys):* `HS256`, `HS384`, `HS512`
  # - *RSASSA-PSS (RSA keys):* `PS256`, `PS384`, `PS512`
  # - *RSASSA-PKCS#1.5 (RSA keys):* `RS256`, `RS384`, `RS512`
  #
  # Algorithm defaults inferred from key type when not provided:
  # EC → `"ES256"`, RSA → `"RS256"`, oct → `"HS256"`, OKP → `"EdDSA"`.
  module JWS
    # Signs *plain_text* with *jwk* and returns a compact `SignedBinary`.
    #
    # The algorithm is taken from `header_overrides["alg"]` when present;
    # otherwise it is inferred from *jwk*'s key type (see module doc for
    # defaults). *header_overrides* may also carry `"kid"` and any custom
    # header fields.
    #
    # ```
    # jwk = JOSE::JWK.generate_key({"kty" => JSON::Any.new("EC"), "crv" => JSON::Any.new("P-256")})
    # signed = JOSE::JWS.sign(jwk, "{\"sub\":\"alice\"}")
    # valid, payload = JOSE::JWS.verify(jwk, signed)
    # ```
    def self.sign(jwk : JWK, plain_text : String,
                  header_overrides : Hash(String, JSON::Any)? = nil) : SignedBinary
      alg = header_overrides.try(&.["alg"]?.try(&.as_s)) || default_alg(jwk)

      header = {"alg" => JSON::Any.new(alg)} of String => JSON::Any
      kid = jwk["kid"]?.try(&.as_s)
      header["kid"] = JSON::Any.new(kid) if kid
      header_overrides.try &.each { |k, v| header[k] = v }

      b64 = header_overrides.try { |hdrs| hdrs["b64"]? }.try(&.raw) != false

      unless b64
        raise ArgumentError.new("Unencoded JWS payload must not contain '.' (RFC 7797 §7)") if plain_text.includes?('.')
        existing_crit = header["crit"]?.try(&.as_a.map(&.as_s)) || [] of String
        unless existing_crit.includes?("b64")
          header["crit"] = JSON::Any.new((existing_crit + ["b64"]).map { |str| JSON::Any.new(str) })
        end
      end

      header_b64 = Base64Url.encode(header.to_json.to_slice)
      payload_part = b64 ? Base64Url.encode(plain_text.to_slice) : plain_text
      signing_input = "#{header_b64}.#{payload_part}"
      sig = compute_signature(jwk, alg, signing_input.to_slice)
      SignedBinary.new("#{signing_input}.#{Base64Url.encode(sig)}")
    end

    # Verifies a compact JWS using *jwk*.
    #
    # *signed* may be a raw compact serialization `String` or a `SignedBinary`.
    # Returns `{valid, payload}` where *valid* is `true` when the signature
    # checks out and *payload* is the decoded payload string regardless of
    # validity. Raises `ArgumentError` if the token does not have three parts.
    #
    # Pass *detached* (the original plain-text payload) when verifying a token
    # with detached content (RFC 7515 §7): the compact token must have an empty
    # middle segment (`header..signature`) and the caller supplies the payload
    # out-of-band. Raises `ArgumentError` if *detached* is given but the token's
    # payload segment is non-empty.
    def self.verify(jwk : JWK, signed : String | SignedBinary,
                    detached : String? = nil) : {Bool, String}
      compact = signed.is_a?(SignedBinary) ? signed.compact : signed
      parts = compact.split('.')
      raise ArgumentError.new("Invalid compact JWS") unless parts.size == 3

      header = JSON.parse(String.new(Base64Url.decode(parts[0]))).as_h
      alg = header["alg"].as_s
      sig = Base64Url.decode(parts[2])
      b64 = header["b64"]?.try(&.as_bool) != false

      if detached
        raise ArgumentError.new("Compact JWS has non-empty payload segment; cannot use detached:") unless parts[1].empty?
        payload_part = b64 ? Base64Url.encode(detached.to_slice) : detached
        signing_input = "#{parts[0]}.#{payload_part}"
        payload = detached
      else
        signing_input = "#{parts[0]}.#{parts[1]}"
        payload = b64 ? String.new(Base64Url.decode(parts[1])) : parts[1]
      end

      valid = verify_signature(jwk, alg, signing_input.to_slice, sig)
      {valid, payload}
    end

    # ── JSON Serialization (RFC 7515 §7.2) ────────────────────────────────────

    # Verifies a JWS JSON Serialization using *jwk*.
    #
    # Accepts both the **flattened** form
    # `{"payload":…,"protected":…,"header":…,"signature":…}` and the
    # **general** form `{"payload":…,"signatures":[…]}`. For the general form
    # every signature entry is tried in order; `{true, payload}` is returned on
    # the first entry that verifies against *jwk*. Returns `{false, payload}`
    # when no entry verifies. The `alg` value is taken from the protected header
    # first, then from the unprotected header.
    def self.verify_json(jwk : JWK, json : String) : {Bool, String}
      parsed = JSON.parse(json).as_h
      payload_raw = parsed["payload"].as_s

      entries = parsed["signatures"]?.try { |sigs| sigs.as_a.map(&.as_h) } || [parsed]

      last_b64 = true
      entries.each do |entry|
        protected_b64 = entry["protected"]?.try(&.as_s) || ""
        unprotected_h = entry["header"]?.try(&.as_h)
        sig = Base64Url.decode(entry["signature"].as_s)

        protected_h = protected_b64.empty? ? {} of String => JSON::Any : JSON.parse(String.new(Base64Url.decode(protected_b64))).as_h

        alg = (protected_h["alg"]? || unprotected_h.try(&.["alg"]?)).try(&.as_s)
        next unless alg

        b64 = protected_h["b64"]?.try(&.as_bool) != false
        last_b64 = b64
        payload = b64 ? String.new(Base64Url.decode(payload_raw)) : payload_raw
        signing_input = "#{protected_b64}.#{payload_raw}"
        valid = begin
          verify_signature(jwk, alg, signing_input.to_slice, sig)
        rescue
          false
        end
        return {true, payload} if valid
      end

      payload = last_b64 ? String.new(Base64Url.decode(payload_raw)) : payload_raw
      {false, payload}
    end

    # Signs *plain_text* and returns a **JWS Flattened JSON Serialization**.
    #
    # Fields in *protected_overrides* go into the signed protected header.
    # Fields in *unprotected* go into the unsigned per-signature header. When
    # *unprotected* carries `"alg"` the protected header will contain no `"alg"`
    # entry (§4.7 style — protected header omitted entirely if it stays empty).
    # The `kid` from *jwk* is added to the protected header when neither
    # *protected_overrides* nor *unprotected* already carry it.
    def self.sign_json(jwk : JWK, plain_text : String,
                       protected_overrides : Hash(String, JSON::Any)? = nil,
                       unprotected : Hash(String, JSON::Any)? = nil) : String
      alg = protected_overrides.try(&.["alg"]?.try(&.as_s)) ||
            unprotected.try(&.["alg"]?.try(&.as_s)) ||
            default_alg(jwk)

      prot = {} of String => JSON::Any
      protected_overrides.try &.each { |k, v| prot[k] = v }
      unless prot.has_key?("alg") || unprotected.try(&.has_key?("alg"))
        prot["alg"] = JSON::Any.new(alg)
      end
      kid = jwk["kid"]?.try(&.as_s)
      if kid && !prot.has_key?("kid") && !unprotected.try(&.has_key?("kid"))
        prot["kid"] = JSON::Any.new(kid)
      end

      b64 = protected_overrides.try { |hdrs| hdrs["b64"]? }.try(&.raw) != false

      unless b64
        existing_crit = prot["crit"]?.try(&.as_a.map(&.as_s)) || [] of String
        unless existing_crit.includes?("b64")
          prot["crit"] = JSON::Any.new((existing_crit + ["b64"]).map { |str| JSON::Any.new(str) })
        end
      end

      payload_part = b64 ? Base64Url.encode(plain_text.to_slice) : plain_text
      protected_b64 = prot.empty? ? "" : Base64Url.encode(prot.to_json.to_slice)
      signing_input = "#{protected_b64}.#{payload_part}"
      sig_b64 = Base64Url.encode(compute_signature(jwk, alg, signing_input.to_slice))

      result = {} of String => JSON::Any
      result["payload"] = JSON::Any.new(payload_part)
      result["protected"] = JSON::Any.new(protected_b64) unless protected_b64.empty?
      unprotected.try { |hdr| result["header"] = JSON::Any.new(hdr) }
      result["signature"] = JSON::Any.new(sig_b64)
      result.to_json
    end

    # ── Peek helpers ──────────────────────────────────────────────────────────

    # Returns the decoded protected header from *compact* without verifying.
    def self.peek_protected(compact : String) : Hash(String, JSON::Any)
      JSON.parse(String.new(Base64Url.decode(compact.split('.').first))).as_h
    end

    # Returns the decoded payload string from *compact* without verifying.
    def self.peek_payload(compact : String) : String
      p = compact.split('.')
      header = JSON.parse(String.new(Base64Url.decode(p[0]))).as_h
      header["b64"]?.try(&.as_bool) != false ? String.new(Base64Url.decode(p[1])) : p[1]
    end

    # Returns the raw signature bytes from *compact* without verifying.
    def self.peek_signature(compact : String) : Bytes
      Base64Url.decode(compact.split('.')[2])
    end

    # ── Private helpers ───────────────────────────────────────────────────────

    private def self.default_alg(jwk : JWK) : String
      case jwk.kty
      when "EC"  then "ES256"
      when "RSA" then "RS256"
      when "oct" then "HS256"
      when "OKP" then "EdDSA"
      else            raise ArgumentError.new("Cannot infer JWS alg for kty=#{jwk.kty}")
      end
    end

    private def self.compute_signature(jwk : JWK, alg : String, input : Bytes) : Bytes
      case alg
      when "HS256" then OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, jwk.key_bytes, input)
      when "HS384" then OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA384, jwk.key_bytes, input)
      when "HS512" then OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA512, jwk.key_bytes, input)
      when "ES256", "ES384", "ES512"
        ecdsa_sign(jwk, alg, input)
      when "RS256" then rsa_pkcs1_sign(jwk, LibCrypto.evp_sha256, input)
      when "RS384" then rsa_pkcs1_sign(jwk, LibCrypto.evp_sha384, input)
      when "RS512" then rsa_pkcs1_sign(jwk, LibCrypto.evp_sha512, input)
      when "PS256" then rsa_pss_sign(jwk, LibCrypto.evp_sha256, input)
      when "PS384" then rsa_pss_sign(jwk, LibCrypto.evp_sha384, input)
      when "PS512" then rsa_pss_sign(jwk, LibCrypto.evp_sha512, input)
      when "EdDSA" then edsa_sign(jwk, input)
      else              raise ArgumentError.new("Unsupported JWS alg: #{alg}")
      end
    end

    private def self.verify_signature(jwk : JWK, alg : String, input : Bytes, sig : Bytes) : Bool
      case alg
      when "HS256"
        expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA256, jwk.key_bytes, input)
        constant_time_eq(expected, sig)
      when "HS384"
        expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA384, jwk.key_bytes, input)
        constant_time_eq(expected, sig)
      when "HS512"
        expected = OpenSSL::HMAC.digest(OpenSSL::Algorithm::SHA512, jwk.key_bytes, input)
        constant_time_eq(expected, sig)
      when "ES256", "ES384", "ES512"
        ecdsa_verify(jwk, alg, input, sig)
      when "RS256" then rsa_pkcs1_verify(jwk, LibCrypto.evp_sha256, input, sig)
      when "RS384" then rsa_pkcs1_verify(jwk, LibCrypto.evp_sha384, input, sig)
      when "RS512" then rsa_pkcs1_verify(jwk, LibCrypto.evp_sha512, input, sig)
      when "PS256" then rsa_pss_verify(jwk, LibCrypto.evp_sha256, input, sig)
      when "PS384" then rsa_pss_verify(jwk, LibCrypto.evp_sha384, input, sig)
      when "PS512" then rsa_pss_verify(jwk, LibCrypto.evp_sha512, input, sig)
      when "EdDSA" then edsa_verify(jwk, input, sig)
      else              raise ArgumentError.new("Unsupported JWS alg: #{alg}")
      end
    end

    # ── HMAC ──────────────────────────────────────────────────────────────────

    private def self.constant_time_eq(a : Bytes, b : Bytes) : Bool
      return false unless a.size == b.size
      result = 0_u8
      a.size.times { |i| result |= a[i] ^ b[i] }
      result == 0
    end

    # ── ECDSA ─────────────────────────────────────────────────────────────────

    private def self.ecdsa_sign(jwk : JWK, alg : String, input : Bytes) : Bytes
      coord_size = ecdsa_coord_size(alg)
      md = ecdsa_md(alg)

      ec_key = jwk.ec_private_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_EC_KEY(pkey, ec_key)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            ret = LibCryptoJose.EVP_DigestSignInit(ctx, Pointer(LibCryptoJose::EVP_PKEY_CTX).null, md, Pointer(Void).null, pkey)
            raise "EVP_DigestSignInit failed" unless ret == 1
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            sig_len = LibC::SizeT.new(0)
            LibCryptoJose.EVP_DigestSignFinal(ctx, Pointer(UInt8).null, pointerof(sig_len))
            der_sig = Bytes.new(sig_len)
            ret = LibCryptoJose.EVP_DigestSignFinal(ctx, der_sig, pointerof(sig_len))
            raise "EVP_DigestSignFinal failed" unless ret == 1
            der_to_raw(der_sig[0, sig_len.to_i], coord_size)
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCrypto.ec_key_free(ec_key)
      end
    end

    private def self.ecdsa_verify(jwk : JWK, alg : String, input : Bytes, raw_sig : Bytes) : Bool
      coord_size = ecdsa_coord_size(alg)
      md = ecdsa_md(alg)

      ec_key = jwk.ec_public_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_EC_KEY(pkey, ec_key)
          der_sig = raw_to_der(raw_sig, coord_size)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            ret = LibCryptoJose.EVP_DigestVerifyInit(ctx, Pointer(LibCryptoJose::EVP_PKEY_CTX).null, md, Pointer(Void).null, pkey)
            raise "EVP_DigestVerifyInit failed" unless ret == 1
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            ret = LibCryptoJose.EVP_DigestVerifyFinal(ctx, der_sig, der_sig.size)
            ret == 1
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCrypto.ec_key_free(ec_key)
      end
    end

    # Converts DER-encoded ECDSA signature to raw r‖s (zero-padded to coord_size each).
    private def self.der_to_raw(der : Bytes, coord_size : Int32) : Bytes
      ptr = der.to_unsafe
      sig = LibCryptoJose.d2i_ECDSA_SIG(Pointer(LibCryptoJose::ECDSA_SIG).null, pointerof(ptr), der.size.to_i64)
      raise "d2i_ECDSA_SIG failed" if sig.null?
      begin
        r_bn = LibCryptoJose::BIGNUM.null
        s_bn = LibCryptoJose::BIGNUM.null
        LibCryptoJose.ECDSA_SIG_get0(sig, pointerof(r_bn), pointerof(s_bn))

        result = Bytes.new(coord_size * 2, 0x00_u8)
        r_len = (LibCryptoJose.BN_num_bits(r_bn) + 7) // 8
        s_len = (LibCryptoJose.BN_num_bits(s_bn) + 7) // 8
        LibCryptoJose.BN_bn2bin(r_bn, result.to_unsafe + (coord_size - r_len))
        LibCryptoJose.BN_bn2bin(s_bn, result.to_unsafe + coord_size + (coord_size - s_len))
        result
      ensure
        LibCryptoJose.ECDSA_SIG_free(sig)
      end
    end

    # Converts raw r‖s to DER-encoded ECDSA signature.
    private def self.raw_to_der(raw : Bytes, coord_size : Int32) : Bytes
      r_bytes = raw[0, coord_size]
      s_bytes = raw[coord_size, coord_size]

      r_bn = LibCryptoJose.BN_bin2bn(r_bytes, r_bytes.size, LibCryptoJose::BIGNUM.null)
      s_bn = LibCryptoJose.BN_bin2bn(s_bytes, s_bytes.size, LibCryptoJose::BIGNUM.null)
      raise "BN_bin2bn failed" if r_bn.null? || s_bn.null?

      sig = LibCryptoJose.ECDSA_SIG_new
      raise "ECDSA_SIG_new failed" if sig.null?
      # set0 transfers ownership of r_bn and s_bn to sig
      ret = LibCryptoJose.ECDSA_SIG_set0(sig, r_bn, s_bn)
      raise "ECDSA_SIG_set0 failed" unless ret == 1

      begin
        der_ptr = Pointer(UInt8).null
        der_len = LibCryptoJose.i2d_ECDSA_SIG(sig, pointerof(der_ptr))
        raise "i2d_ECDSA_SIG failed" if der_len <= 0
        Bytes.new(der_ptr, der_len).dup
      ensure
        LibCryptoJose.ECDSA_SIG_free(sig)
      end
    end

    private def self.ecdsa_coord_size(alg : String) : Int32
      case alg
      when "ES256" then 32
      when "ES384" then 48
      when "ES512" then 66
      else              raise ArgumentError.new("Unknown ECDSA alg: #{alg}")
      end
    end

    private def self.ecdsa_md(alg : String) : LibCrypto::EVP_MD
      case alg
      when "ES256" then LibCrypto.evp_sha256
      when "ES384" then LibCrypto.evp_sha384
      when "ES512" then LibCrypto.evp_sha512
      else              raise ArgumentError.new("Unknown ECDSA alg: #{alg}")
      end
    end

    # ── RSA PKCS1 v1.5 ───────────────────────────────────────────────────────

    private def self.rsa_pkcs1_sign(jwk : JWK, md : LibCrypto::EVP_MD, input : Bytes) : Bytes
      rsa = jwk.rsa_raw_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            ret = LibCryptoJose.EVP_DigestSignInit(ctx, Pointer(LibCryptoJose::EVP_PKEY_CTX).null, md, Pointer(Void).null, pkey)
            raise "EVP_DigestSignInit failed" unless ret == 1
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            sig_len = LibC::SizeT.new(0)
            LibCryptoJose.EVP_DigestSignFinal(ctx, Pointer(UInt8).null, pointerof(sig_len))
            sig = Bytes.new(sig_len)
            ret = LibCryptoJose.EVP_DigestSignFinal(ctx, sig, pointerof(sig_len))
            raise "EVP_DigestSignFinal failed" unless ret == 1
            sig[0, sig_len.to_i]
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    private def self.rsa_pkcs1_verify(jwk : JWK, md : LibCrypto::EVP_MD, input : Bytes, sig : Bytes) : Bool
      rsa = jwk.rsa_raw_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            ret = LibCryptoJose.EVP_DigestVerifyInit(ctx, Pointer(LibCryptoJose::EVP_PKEY_CTX).null, md, Pointer(Void).null, pkey)
            raise "EVP_DigestVerifyInit failed" unless ret == 1
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            ret = LibCryptoJose.EVP_DigestVerifyFinal(ctx, sig, sig.size)
            ret == 1
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    # ── RSA PSS ───────────────────────────────────────────────────────────────

    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
      private def self.configure_pss_pctx(pctx : LibCryptoJose::EVP_PKEY_CTX)
        LibCryptoJose.EVP_PKEY_CTX_set_rsa_padding(pctx, LibCryptoJose::RSA_PKCS1_PSS_PADDING)
        LibCryptoJose.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1)
      end
    {% else %}
      private def self.configure_pss_pctx(pctx : LibCryptoJose::EVP_PKEY_CTX)
        LibCryptoJose.EVP_PKEY_CTX_ctrl(pctx, LibCryptoJose::EVP_PKEY_RSA, -1,
          LibCryptoJose::EVP_PKEY_CTRL_RSA_PADDING, LibCryptoJose::RSA_PKCS1_PSS_PADDING, Pointer(Void).null)
        LibCryptoJose.EVP_PKEY_CTX_ctrl(pctx, LibCryptoJose::EVP_PKEY_RSA, -1,
          LibCryptoJose::EVP_PKEY_CTRL_RSA_PSS_SALTLEN, -1, Pointer(Void).null)
      end
    {% end %}

    private def self.rsa_pss_sign(jwk : JWK, md : LibCrypto::EVP_MD, input : Bytes) : Bytes
      rsa = jwk.rsa_raw_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            pctx = LibCryptoJose::EVP_PKEY_CTX.null
            ret = LibCryptoJose.EVP_DigestSignInit(ctx, pointerof(pctx), md, Pointer(Void).null, pkey)
            raise "EVP_DigestSignInit failed" unless ret == 1
            configure_pss_pctx(pctx)
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            sig_len = LibC::SizeT.new(0)
            LibCryptoJose.EVP_DigestSignFinal(ctx, Pointer(UInt8).null, pointerof(sig_len))
            sig = Bytes.new(sig_len)
            ret = LibCryptoJose.EVP_DigestSignFinal(ctx, sig, pointerof(sig_len))
            raise "EVP_DigestSignFinal failed" unless ret == 1
            sig[0, sig_len.to_i]
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    private def self.rsa_pss_verify(jwk : JWK, md : LibCrypto::EVP_MD, input : Bytes, sig : Bytes) : Bool
      rsa = jwk.rsa_raw_key
      begin
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
          ctx = LibCrypto.evp_md_ctx_new
          raise "EVP_MD_CTX_new failed" if ctx.null?
          begin
            pctx = LibCryptoJose::EVP_PKEY_CTX.null
            ret = LibCryptoJose.EVP_DigestVerifyInit(ctx, pointerof(pctx), md, Pointer(Void).null, pkey)
            raise "EVP_DigestVerifyInit failed" unless ret == 1
            configure_pss_pctx(pctx)
            ret = LibCrypto.evp_digestupdate(ctx, input, input.size)
            raise "EVP_DigestUpdate failed" unless ret == 1
            ret = LibCryptoJose.EVP_DigestVerifyFinal(ctx, sig, sig.size)
            ret == 1
          ensure
            LibCrypto.evp_md_ctx_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    # ── EdDSA (Ed25519) ───────────────────────────────────────────────────────

    private def self.edsa_sign(jwk : JWK, input : Bytes) : Bytes
      signing_key = jwk.ed25519_signing_key
      signing_key.sign(input)
    end

    private def self.edsa_verify(jwk : JWK, input : Bytes, sig : Bytes) : Bool
      verify_key = jwk.ed25519_verify_key
      verify_key.verify(sig, input)
      true
    rescue Ed25519::VerifyError
      false
    end
  end
end
