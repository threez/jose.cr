module JOSE
  # Represents a JSON Web Key (JWK) for EC, RSA, oct, and OKP key types.
  class JWK
    # The underlying JSON map holding all key parameters.
    getter map : Hash(String, JSON::Any)

    def initialize(@map : Hash(String, JSON::Any))
    end

    # ── Constructors ─────────────────────────────────────────────────────────

    # Constructs a `JWK` wrapping the given *map*.
    def self.from_map(map : Hash(String, JSON::Any)) : JWK
      new(map)
    end

    # Constructs a `JWK` wrapping *map* with *overrides* merged in.
    # String overrides are automatically boxed into `JSON::Any`.
    #
    # ```
    # JOSE::JWK.from_map(k1.map, kid: "sig")
    # ```
    def self.from_map(map : Hash(String, JSON::Any), **overrides : String) : JWK
      override_map = {} of String => JSON::Any
      overrides.each { |k, v| override_map[k.to_s] = JSON::Any.new(v) }
      new(map.merge(override_map))
    end

    # Parses *json* and returns the resulting `JWK`.
    def self.from_binary(json : String) : JWK
      new(JSON.parse(json).as_h)
    end

    # Creates an oct (symmetric) JWK from raw key bytes.
    def self.from_oct(key : Bytes) : JWK
      map = JSON.parse({
        "kty" => "oct",
        "k"   => Base64Url.encode(key),
      }.to_json).as_h
      new(map)
    end

    # Loads an EC or RSA key from PEM and returns the corresponding `JWK`.
    # Returns a JWK with private fields if the PEM contains a private key,
    # or a public-only JWK if it contains only a public key.
    #
    # Accepted PEM formats and the OpenSSL commands that produce them:
    #
    # ```bash
    # # EC private key  (SEC 1 / RFC 5915)
    # openssl ecparam -name prime256v1 -genkey -noout -out ec-p256.pem
    #
    # # EC public key  (SubjectPublicKeyInfo)
    # openssl ec -in ec-p256.pem -pubout -out ec-p256-pub.pem
    #
    # # RSA private key  (PKCS#1)
    # openssl genrsa -out rsa-2048.pem 2048
    #
    # # RSA public key  (SubjectPublicKeyInfo)
    # openssl rsa -in rsa-2048.pem -pubout -out rsa-2048-pub.pem
    # ```
    #
    # ```
    # jwk = JOSE::JWK.from_pem(File.read("ec-p256.pem"))
    # ```
    def self.from_pem(pem : String) : JWK
      pem_bytes = pem.to_slice
      bio = LibCryptoJose.BIO_new_mem_buf(pem_bytes.to_unsafe.as(Void*), pem_bytes.size)
      raise "BIO_new_mem_buf failed" if bio.null?
      begin
        # Try RSA private
        rsa = LibCryptoJose.PEM_read_bio_RSAPrivateKey(bio, Pointer(LibCryptoJose::RSA).null, Pointer(Void).null, Pointer(Void).null)
        unless rsa.null?
          map = rsa_to_jwk_map(rsa, private_key: true)
          LibCryptoJose.RSA_free(rsa)
          return new(map)
        end

        # Rewind bio
        LibCrypto.BIO_free(bio)
        bio = LibCryptoJose.BIO_new_mem_buf(pem_bytes.to_unsafe.as(Void*), pem_bytes.size)

        # Try RSA public
        rsa = LibCryptoJose.PEM_read_bio_RSA_PUBKEY(bio, Pointer(LibCryptoJose::RSA).null, Pointer(Void).null, Pointer(Void).null)
        unless rsa.null?
          map = rsa_to_jwk_map(rsa, private_key: false)
          LibCryptoJose.RSA_free(rsa)
          return new(map)
        end

        # Rewind bio
        LibCrypto.BIO_free(bio)
        bio = LibCryptoJose.BIO_new_mem_buf(pem_bytes.to_unsafe.as(Void*), pem_bytes.size)

        # Try EC private
        ec = LibCryptoJose.PEM_read_bio_ECPrivateKey(bio, nil, Pointer(Void).null, Pointer(Void).null)
        unless ec.null?
          map = ec_to_jwk_map(ec, private_key: true)
          LibCrypto.ec_key_free(ec)
          return new(map)
        end

        # Rewind bio
        LibCrypto.BIO_free(bio)
        bio = LibCryptoJose.BIO_new_mem_buf(pem_bytes.to_unsafe.as(Void*), pem_bytes.size)

        # Try EC public
        ec = LibCryptoJose.PEM_read_bio_EC_PUBKEY(bio, nil, Pointer(Void).null, Pointer(Void).null)
        unless ec.null?
          map = ec_to_jwk_map(ec, private_key: false)
          LibCrypto.ec_key_free(ec)
          return new(map)
        end

        raise ArgumentError.new("Could not parse PEM as EC or RSA key")
      ensure
        LibCrypto.BIO_free(bio) unless bio.null?
      end
    end

    # Generates a new key according to *params*.
    #
    # The *params* hash must contain at least `"kty"` and, depending on the
    # key type, optional shape keys:
    #
    # - `"EC"`  — `"crv"`: curve name (`"P-256"` … `"P-521"`), default `"P-256"`
    # - `"RSA"` — `"bits"`: key size in bits, default `2048`
    # - `"oct"` — `"size"`: key length in bytes, default `32`
    # - `"OKP"` — `"crv"`: curve name (`"Ed25519"`), default `"Ed25519"`
    #
    # NOTE: RSA key generation is synchronous and may take a moment for large
    # bit sizes. EC and OKP generation is near-instant.
    #
    # **Using OpenSSL to generate keys externally:**
    #
    # ```bash
    # # EC
    # openssl ecparam -name prime256v1 -genkey -noout -out ec-p256.pem
    # # RSA
    # openssl genrsa -out rsa-2048.pem 2048
    # ```
    #
    # Load with `JWK.from_pem(File.read("ec-p256.pem"))`.
    #
    # Prefer the typed convenience wrappers `generate_key_ec`, `generate_key_rsa`,
    # `generate_key_oct`, and `generate_key_okp` for common cases.
    #
    # ```
    # ec_key = JOSE::JWK.generate_key({"kty" => JSON::Any.new("EC"), "crv" => JSON::Any.new("P-384")})
    # rsa_key = JOSE::JWK.generate_key({"kty" => JSON::Any.new("RSA"), "bits" => JSON::Any.new(2048_i64)})
    # sym_key = JOSE::JWK.generate_key({"kty" => JSON::Any.new("oct"), "size" => JSON::Any.new(32_i64)})
    # okp_key = JOSE::JWK.generate_key({"kty" => JSON::Any.new("OKP"), "crv" => JSON::Any.new("Ed25519")})
    # ```
    def self.generate_key(params : Hash(String, JSON::Any)) : JWK
      kty = params["kty"]?.try(&.as_s) || raise ArgumentError.new("Missing kty")
      case kty
      when "EC"
        crv = params["crv"]?.try(&.as_s) || "P-256"
        nid = JWA::ECDH_ES.nid_for_crv(crv)
        key = LibCrypto.ec_key_new_by_curve_name(nid)
        raise "EC_KEY_new_by_curve_name failed" if key.null?
        begin
          LibCryptoJose.EC_KEY_generate_key(key)
          map = ec_to_jwk_map(key, private_key: true)
          new(map)
        ensure
          LibCrypto.ec_key_free(key)
        end
      when "RSA"
        bits = params["bits"]?.try(&.as_i) || 2048
        raise ArgumentError.new("RSA key size must be at least 2048 bits (got #{bits})") if bits < 2048
        rsa = LibCryptoJose.RSA_new
        raise "RSA_new failed" if rsa.null?
        begin
          e_bn = LibCryptoJose.BN_new
          raise "BN_new failed" if e_bn.null?
          LibCryptoJose.BN_set_word(e_bn, 65537_u64)
          ret = LibCryptoJose.RSA_generate_key_ex(rsa, bits, e_bn, Pointer(Void).null)
          LibCryptoJose.BN_free(e_bn)
          raise "RSA_generate_key_ex failed" unless ret == 1
          new(rsa_to_jwk_map(rsa, private_key: true))
        ensure
          LibCryptoJose.RSA_free(rsa)
        end
      when "oct"
        size = params["size"]?.try(&.as_i) || 32
        from_oct(Random::Secure.random_bytes(size))
      when "OKP"
        crv = params["crv"]?.try(&.as_s) || "Ed25519"
        raise ArgumentError.new("Only Ed25519 OKP supported") unless crv == "Ed25519"
        signing_key = Ed25519::SigningKey.new
        x_bytes = signing_key.verify_key.key_bytes
        d_bytes = signing_key.key_bytes
        map = JSON.parse({
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x"   => Base64Url.encode(x_bytes),
          "d"   => Base64Url.encode(d_bytes),
        }.to_json).as_h
        new(map)
      else
        raise ArgumentError.new("Unsupported kty: #{kty}")
      end
    end

    private macro def_generate_key(name, kty, param_name, param_default)
      # Generates a new `{{kty}}` key.
      # *{{param_name}}* defaults to `{{param_default}}`. See `generate_key` for details.
      def self.generate_key_{{name}}(
        {{param_name}} : {% if param_default.is_a?(NumberLiteral) %}Int32{% else %}String{% end %} = {{param_default}}
      ) : JWK
        generate_key({
          "kty"                    => JSON::Any.new({{kty}}),
          {{param_name.stringify}} => JSON::Any.new({% if param_default.is_a?(NumberLiteral) %}{{param_name}}.to_i64{% else %}{{param_name}}{% end %}),
        })
      end
    end

    def_generate_key ec, "EC", crv, "P-256"
    def_generate_key rsa, "RSA", bits, 2048
    def_generate_key oct, "oct", size, 32
    def_generate_key okp, "OKP", crv, "Ed25519"

    # ── Accessors ─────────────────────────────────────────────────────────────

    # Returns the value for *key* from the key map.
    def [](key : String) : JSON::Any
      @map[key]
    end

    # Returns the value for *key*, or `nil` if absent.
    def []?(key : String) : JSON::Any?
      @map[key]?
    end

    # Returns the key type (`"EC"`, `"RSA"`, `"oct"`, or `"OKP"`).
    def kty : String
      @map["kty"].as_s
    end

    # Returns `true` if this key contains no private key material.
    def public? : Bool
      case kty
      when "EC"  then @map["d"]?.nil?
      when "RSA" then @map["d"]?.nil?
      when "oct" then true
      when "OKP" then @map["d"]?.nil?
      else            true
      end
    end

    # Returns `true` if this key contains private key material.
    def private? : Bool
      !public?
    end

    # Returns a copy of this JWK with the given string fields merged in.
    # Existing fields are overwritten; all other fields are preserved.
    #
    # ```
    # jwk.with(kid: "sig")
    # jwk.with(kid: "sig", use: "sig", alg: "ES256")
    # ```
    def with(**fields : String) : JWK
      overrides = {} of String => JSON::Any
      fields.each { |k, v| overrides[k.to_s] = JSON::Any.new(v) }
      JWK.new(@map.merge(overrides))
    end

    # Returns a copy of this JWK with all private fields removed.
    def to_public : JWK
      return self if public?
      private_fields = %w[d p q dp dq qi]
      new_map = @map.reject { |k, _| private_fields.includes?(k) }
      JWK.new(new_map)
    end

    # Returns the underlying JSON map.
    def to_map : Hash(String, JSON::Any)
      @map
    end

    # Serializes this key to a JSON string.
    def to_binary : String
      @map.to_json
    end

    # Returns `true` if both JWKs have identical key parameters.
    def ==(other : JWK) : Bool
      @map == other.map
    end

    def hash(hasher)
      @map.hash(hasher)
    end

    # Serializes this key to PEM format.
    def to_pem : String
      case kty
      when "EC"  then ec_to_pem
      when "RSA" then rsa_to_pem
      else            raise ArgumentError.new("to_pem not supported for kty=#{kty}")
      end
    end

    # ── Encryption / Decryption ───────────────────────────────────────────────

    # Encrypts *plain_text* using this key. Delegates to `JWE.block_encrypt`.
    def block_encrypt(plain_text : String, header = nil) : EncryptedBinary
      JWE.block_encrypt(self, plain_text, header)
    end

    # Decrypts *encrypted* using this key. Delegates to `JWE.block_decrypt`.
    def block_decrypt(encrypted : String | EncryptedBinary) : String
      JWE.block_decrypt(self, encrypted)
    end

    # ── Signing / Verification ────────────────────────────────────────────────

    # Signs *plain_text* using this key. Delegates to `JWS.sign`.
    def sign(plain_text : String, header = nil) : SignedBinary
      JWS.sign(self, plain_text, header)
    end

    # Verifies *signed* using this key. Delegates to `JWS.verify`.
    def verify(signed : String | SignedBinary) : {Bool, String}
      JWS.verify(self, signed)
    end

    # ── Internal key accessors (used by JWE / JWS) ───────────────────────────

    # Returns an `EC_KEY` with only the public key set.
    # NOTE: Caller must free the returned key with `LibCrypto.ec_key_free`.
    def ec_public_key : LibCrypto::EC_KEY
      crv = @map["crv"]?.try(&.as_s) || "P-256"
      nid = JWA::ECDH_ES.nid_for_crv(crv)
      field_size = JWA::ECDH_ES.ec_field_size_for_nid(nid)

      x = Base64Url.decode(@map["x"].as_s)
      y = Base64Url.decode(@map["y"].as_s)

      point_bytes = Bytes.new(1 + 2 * field_size, 0x00_u8)
      point_bytes[0] = 0x04_u8
      x.copy_to(point_bytes + (1 + field_size - x.size))
      y.copy_to(point_bytes + (1 + field_size + field_size - y.size))

      key = LibCrypto.ec_key_new_by_curve_name(nid)
      raise "EC_KEY_new_by_curve_name failed" if key.null?

      group = LibCryptoJose.EC_KEY_get0_group(key)
      point = LibCryptoJose.EC_POINT_new(group)
      raise "EC_POINT_new failed" if point.null?

      begin
        ret = LibCryptoJose.EC_POINT_oct2point(group, point, point_bytes, point_bytes.size, Pointer(Void).null)
        raise "EC_POINT_oct2point failed" unless ret == 1
        ret = LibCryptoJose.EC_KEY_set_public_key(key, point)
        raise "EC_KEY_set_public_key failed" unless ret == 1
      ensure
        LibCryptoJose.EC_POINT_free(point)
      end
      key
    end

    # Returns an `EC_KEY` with both public and private key set.
    # NOTE: Caller must free the returned key with `LibCrypto.ec_key_free`.
    def ec_private_key : LibCrypto::EC_KEY
      raise ArgumentError.new("JWK has no private key (d)") unless @map["d"]?
      key = ec_public_key
      d_bytes = Base64Url.decode(@map["d"].as_s)
      bn = LibCryptoJose.BN_bin2bn(d_bytes, d_bytes.size, LibCryptoJose::BIGNUM.null)
      raise "BN_bin2bn failed" if bn.null?
      ret = LibCryptoJose.EC_KEY_set_private_key(key, bn)
      LibCryptoJose.BN_free(bn)
      raise "EC_KEY_set_private_key failed" unless ret == 1
      key
    end

    # Returns the raw `LibCryptoJose::RSA` handle built from this key's parameters.
    # NOTE: Caller must free the returned handle with `LibCryptoJose.RSA_free`.
    def rsa_raw_key : LibCryptoJose::RSA
      n_bytes = Base64Url.decode(@map["n"].as_s)
      key_bits = n_bytes.size * 8
      raise ArgumentError.new("RSA key size must be at least 2048 bits (got #{key_bits})") if key_bits < 2048

      rsa = LibCryptoJose.RSA_new
      raise "RSA_new failed" if rsa.null?

      n_bytes = Base64Url.decode(@map["n"].as_s)
      e_bytes = Base64Url.decode(@map["e"].as_s)

      n_bn = LibCryptoJose.BN_bin2bn(n_bytes, n_bytes.size, LibCryptoJose::BIGNUM.null)
      e_bn = LibCryptoJose.BN_bin2bn(e_bytes, e_bytes.size, LibCryptoJose::BIGNUM.null)
      d_bn = LibCryptoJose::BIGNUM.null

      if d_str = @map["d"]?.try(&.as_s)
        d_bytes = Base64Url.decode(d_str)
        d_bn = LibCryptoJose.BN_bin2bn(d_bytes, d_bytes.size, LibCryptoJose::BIGNUM.null)
      end

      ret = LibCryptoJose.RSA_set0_key(rsa, n_bn, e_bn, d_bn)
      raise "RSA_set0_key failed" unless ret == 1

      if private?
        p_bytes = Base64Url.decode(@map["p"].as_s)
        q_bytes = Base64Url.decode(@map["q"].as_s)
        dp_bytes = Base64Url.decode(@map["dp"].as_s)
        dq_bytes = Base64Url.decode(@map["dq"].as_s)
        qi_bytes = Base64Url.decode(@map["qi"].as_s)

        p_bn = LibCryptoJose.BN_bin2bn(p_bytes, p_bytes.size, LibCryptoJose::BIGNUM.null)
        q_bn = LibCryptoJose.BN_bin2bn(q_bytes, q_bytes.size, LibCryptoJose::BIGNUM.null)
        dp_bn = LibCryptoJose.BN_bin2bn(dp_bytes, dp_bytes.size, LibCryptoJose::BIGNUM.null)
        dq_bn = LibCryptoJose.BN_bin2bn(dq_bytes, dq_bytes.size, LibCryptoJose::BIGNUM.null)
        qi_bn = LibCryptoJose.BN_bin2bn(qi_bytes, qi_bytes.size, LibCryptoJose::BIGNUM.null)

        LibCryptoJose.RSA_set0_factors(rsa, p_bn, q_bn)
        LibCryptoJose.RSA_set0_crt_params(rsa, dp_bn, dq_bn, qi_bn)
      end

      rsa
    end

    # Returns the raw symmetric key bytes for `oct` keys.
    def key_bytes : Bytes
      raise ArgumentError.new("key_bytes only valid for oct kty") unless kty == "oct"
      Base64Url.decode(@map["k"].as_s)
    end

    # Returns the Ed25519 verify key for `OKP` keys.
    def ed25519_verify_key : Ed25519::VerifyKey
      raise ArgumentError.new("ed25519_verify_key only valid for OKP kty") unless kty == "OKP"
      x_bytes = Base64Url.decode(@map["x"].as_s)
      Ed25519::VerifyKey.new(x_bytes)
    end

    # Returns the Ed25519 signing key for `OKP` private keys.
    def ed25519_signing_key : Ed25519::SigningKey
      raise ArgumentError.new("ed25519_signing_key requires private OKP key") unless kty == "OKP" && private?
      d_bytes = Base64Url.decode(@map["d"].as_s)
      Ed25519::SigningKey.new(d_bytes)
    end

    # ── Private helpers ───────────────────────────────────────────────────────

    private def ec_to_pem : String
      key = private? ? ec_private_key : ec_public_key
      begin
        bio = LibCrypto.BIO_new(LibCryptoJose.BIO_s_mem)
        raise "BIO_new failed" if bio.null?
        begin
          if private?
            ret = LibCryptoJose.PEM_write_bio_ECPrivateKey(bio, key, Pointer(Void).null,
              Pointer(UInt8).null, 0, Pointer(Void).null, Pointer(Void).null)
          else
            ret = LibCryptoJose.PEM_write_bio_EC_PUBKEY(bio, key)
          end
          raise "PEM write failed" unless ret == 1
          bio_to_string(bio)
        ensure
          LibCrypto.BIO_free(bio)
        end
      ensure
        LibCrypto.ec_key_free(key)
      end
    end

    private def rsa_to_pem : String
      rsa = rsa_raw_key
      begin
        bio = LibCrypto.BIO_new(LibCryptoJose.BIO_s_mem)
        raise "BIO_new failed" if bio.null?
        begin
          if private?
            ret = LibCryptoJose.PEM_write_bio_RSAPrivateKey(bio, rsa, Pointer(Void).null,
              Pointer(UInt8).null, 0, Pointer(Void).null, Pointer(Void).null)
          else
            ret = LibCryptoJose.PEM_write_bio_RSA_PUBKEY(bio, rsa)
          end
          raise "PEM write failed" unless ret == 1
          bio_to_string(bio)
        ensure
          LibCrypto.BIO_free(bio)
        end
      ensure
        LibCryptoJose.RSA_free(rsa)
      end
    end

    private def bio_to_string(bio : LibCrypto::Bio*) : String
      data_ptr = Pointer(UInt8).null
      len = LibCryptoJose.BIO_ctrl(bio, LibCryptoJose::BIO_CTRL_INFO, 0_i64, pointerof(data_ptr).as(Void*))
      String.new(data_ptr, len.to_i)
    end

    # ── Class-level helpers for from_pem / generate_key ───────────────────────

    private def self.ec_to_jwk_map(key : LibCrypto::EC_KEY, private_key : Bool) : Hash(String, JSON::Any)
      group = LibCryptoJose.EC_KEY_get0_group(key)
      nid = LibCryptoJose.EC_GROUP_get_curve_name(group)
      crv = JWA::ECDH_ES.crv_for_nid(nid)
      field_size = JWA::ECDH_ES.ec_field_size_for_nid(nid)

      pub = LibCryptoJose.EC_KEY_get0_public_key(key)
      buf = Bytes.new(1 + 2 * field_size)
      LibCryptoJose.EC_POINT_point2oct(group, pub, LibCryptoJose::POINT_CONVERSION_UNCOMPRESSED,
        buf, buf.size, Pointer(Void).null)

      x = buf[1, field_size]
      y = buf[1 + field_size, field_size]

      h = {"kty" => "EC", "crv" => crv, "x" => Base64Url.encode(x), "y" => Base64Url.encode(y)}

      if private_key
        priv_bn = LibCryptoJose.EC_KEY_get0_private_key(key)
        unless priv_bn.null?
          d_len = (LibCryptoJose.BN_num_bits(priv_bn) + 7) // 8
          d_buf = Bytes.new(field_size, 0x00_u8)
          LibCryptoJose.BN_bn2bin(priv_bn, d_buf.to_unsafe + (field_size - d_len))
          h = h.merge({"d" => Base64Url.encode(d_buf)})
        end
      end

      JSON.parse(h.to_json).as_h
    end

    private def self.rsa_to_jwk_map(rsa : LibCryptoJose::RSA, private_key : Bool) : Hash(String, JSON::Any)
      h = {
        "kty" => "RSA",
        "n"   => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_n(rsa))),
        "e"   => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_e(rsa))),
      }
      if private_key
        h = h.merge({
          "d"  => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_d(rsa))),
          "p"  => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_p(rsa))),
          "q"  => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_q(rsa))),
          "dp" => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_dmp1(rsa))),
          "dq" => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_dmq1(rsa))),
          "qi" => Base64Url.encode(bn_to_bytes(LibCryptoJose.RSA_get0_iqmp(rsa))),
        })
      end
      JSON.parse(h.to_json).as_h
    end

    private def self.bn_to_bytes(bn : LibCryptoJose::BIGNUM) : Bytes
      return Bytes.empty if bn.null?
      len = (LibCryptoJose.BN_num_bits(bn) + 7) // 8
      return Bytes.new(1, 0x00_u8) if len == 0
      buf = Bytes.new(len)
      LibCryptoJose.BN_bn2bin(bn, buf)
      buf
    end
  end
end
