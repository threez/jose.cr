module JOSE
  module JWA
    # ECDH-ES key agreement with Concat KDF.
    module ECDH_ES
      # Generates a fresh ephemeral EC key pair for the given curve NID.
      # Caller must free with LibCrypto.ec_key_free.
      def self.generate_ephemeral(nid : Int32) : LibCrypto::EC_KEY
        key = LibCrypto.ec_key_new_by_curve_name(nid)
        raise "ec_key_new_by_curve_name failed" if key.null?
        ret = LibCryptoJose.EC_KEY_generate_key(key)
        raise "EC_KEY_generate_key failed" unless ret == 1
        key
      end

      # Computes ECDH shared secret between our private key and the other party's
      # public key. Returns the x-coordinate (Z_AB) as bytes.
      # Caller is responsible for freeing both keys if needed.
      def self.compute_shared_secret(our_private : LibCrypto::EC_KEY,
                                     their_public : LibCrypto::EC_KEY) : Bytes
        our_pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if our_pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_EC_KEY(our_pkey, our_private)
          their_pkey = LibCryptoJose.EVP_PKEY_new
          raise "EVP_PKEY_new failed" if their_pkey.null?
          begin
            LibCryptoJose.EVP_PKEY_set1_EC_KEY(their_pkey, their_public)
            ctx = LibCryptoJose.EVP_PKEY_CTX_new(our_pkey, Pointer(Void).null)
            raise "EVP_PKEY_CTX_new failed" if ctx.null?
            begin
              raise "EVP_PKEY_derive_init failed" unless LibCryptoJose.EVP_PKEY_derive_init(ctx) == 1
              raise "EVP_PKEY_derive_set_peer failed" unless LibCryptoJose.EVP_PKEY_derive_set_peer(ctx, their_pkey) == 1
              key_len = LibC::SizeT.new(0)
              LibCryptoJose.EVP_PKEY_derive(ctx, Pointer(UInt8).null, pointerof(key_len))
              buf = Bytes.new(key_len)
              raise "EVP_PKEY_derive failed" unless LibCryptoJose.EVP_PKEY_derive(ctx, buf, pointerof(key_len)) == 1
              buf[0, key_len.to_i]
            ensure
              LibCryptoJose.EVP_PKEY_CTX_free(ctx)
            end
          ensure
            LibCryptoJose.EVP_PKEY_free(their_pkey)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(our_pkey)
        end
      end

      # Derives a symmetric key via Concat KDF (SHA-256 single-pass).
      def self.derive_key(shared_secret : Bytes, algorithm : String, key_bits : Int32,
                          apu : Bytes = Bytes.empty, apv : Bytes = Bytes.empty) : Bytes
        ConcatKDF.derive(shared_secret, algorithm, key_bits, apu, apv)
      end

      # Returns uncompressed public key bytes (04 ‖ x ‖ y) for an EC key.
      def self.public_key_bytes(key : LibCrypto::EC_KEY) : Bytes
        field_size = ec_field_size(key)
        point_len = 1 + 2 * field_size
        group = LibCryptoJose.EC_KEY_get0_group(key)
        pub = LibCryptoJose.EC_KEY_get0_public_key(key)
        buf = Bytes.new(point_len)
        len = LibCryptoJose.EC_POINT_point2oct(group, pub, LibCryptoJose::POINT_CONVERSION_UNCOMPRESSED,
          buf, point_len, Pointer(Void).null)
        raise "EC_POINT_point2oct failed" if len == 0
        buf[0, len.to_i]
      end

      # Returns the field coordinate size in bytes for the curve of *key*.
      def self.ec_field_size(key : LibCrypto::EC_KEY) : Int32
        group = LibCryptoJose.EC_KEY_get0_group(key)
        nid = LibCryptoJose.EC_GROUP_get_curve_name(group)
        ec_field_size_for_nid(nid)
      end

      # Returns the field coordinate byte length for the given curve *nid*
      # (32 for P-256, 48 for P-384, or 66 for P-521).
      def self.ec_field_size_for_nid(nid : Int32) : Int32
        case nid
        when LibCrypto::NID_X9_62_prime256v1 then 32
        when LibCryptoJose::NID_secp384r1    then 48
        when LibCryptoJose::NID_secp521r1    then 66
        else                                      raise "Unsupported curve NID #{nid}"
        end
      end

      # Returns the OpenSSL NID for the JWK *crv* string
      # (`"P-256"`, `"P-384"`, or `"P-521"`).
      def self.nid_for_crv(crv : String) : Int32
        case crv
        when "P-256" then LibCrypto::NID_X9_62_prime256v1
        when "P-384" then LibCryptoJose::NID_secp384r1
        when "P-521" then LibCryptoJose::NID_secp521r1
        else              raise ArgumentError.new("Unsupported EC curve: #{crv}")
        end
      end

      # Returns the JWK *crv* string for a curve *nid*.
      def self.crv_for_nid(nid : Int32) : String
        case nid
        when LibCrypto::NID_X9_62_prime256v1 then "P-256"
        when LibCryptoJose::NID_secp384r1    then "P-384"
        when LibCryptoJose::NID_secp521r1    then "P-521"
        else                                      raise "Unsupported NID: #{nid}"
        end
      end
    end
  end
end
