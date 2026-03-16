module JOSE
  module JWA
    # PBES2 key derivation for PBES2-HS256+A128KW, PBES2-HS384+A192KW, and
    # PBES2-HS512+A256KW per RFC 7518 §4.8.
    #
    # The PBKDF2 salt is constructed as `UTF8(alg) || 0x00 || p2s` where *p2s*
    # is the raw salt-input bytes (decoded from the header's base64url `p2s`
    # field).  The HMAC digest and output key length depend on the algorithm:
    #
    # - `PBES2-HS256+A128KW` — SHA-256, 16-byte key
    # - `PBES2-HS384+A192KW` — SHA-384, 24-byte key
    # - `PBES2-HS512+A256KW` — SHA-512, 32-byte key
    module PBES2
      # Derives a key-encryption key (KEK) from *password_bytes* using
      # PBKDF2-HMAC with the parameters encoded in *alg*.
      #
      # *p2s* is the raw (decoded) salt input — the algorithm prefix is
      # prepended internally.  *iterations* maps to `p2c` in the JWE header.
      def self.derive_key(password_bytes : Bytes, alg : String,
                          p2s : Bytes, iterations : Int32) : Bytes
        key_len, digest = alg_params(alg)

        # Build PBKDF2 salt: UTF8(alg) || 0x00 || p2s  (RFC 7518 §4.8.1.1)
        alg_bytes = alg.to_slice
        salt = Bytes.new(alg_bytes.size + 1 + p2s.size)
        alg_bytes.copy_to(salt)
        salt[alg_bytes.size] = 0u8
        p2s.copy_to(salt[alg_bytes.size + 1, p2s.size])

        out_key = Bytes.new(key_len)
        ret = LibCryptoJose.PKCS5_PBKDF2_HMAC(
          password_bytes, password_bytes.size,
          salt, salt.size,
          iterations, digest,
          key_len, out_key
        )
        raise "PKCS5_PBKDF2_HMAC failed" unless ret == 1
        out_key
      end

      private def self.alg_params(alg : String) : {Int32, LibCrypto::EVP_MD}
        case alg
        when "PBES2-HS256+A128KW" then {16, LibCrypto.evp_sha256}
        when "PBES2-HS384+A192KW" then {24, LibCrypto.evp_sha384}
        when "PBES2-HS512+A256KW" then {32, LibCrypto.evp_sha512}
        else                           raise ArgumentError.new("Unknown PBES2 alg: #{alg}")
        end
      end
    end
  end
end
