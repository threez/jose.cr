module JOSE
  module JWA
    # RSA key transport — RFC 7518 §4.1–4.3.
    # All methods accept a raw LibCryptoJose::RSA pointer (no JWK awareness).
    # Callers are responsible for freeing the RSA key.
    module RSA_KW
      def self.encrypt(rsa : LibCryptoJose::RSA, plaintext : Bytes, mode : Symbol) : Bytes
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
          oaep256_op(rsa, plaintext, true)
        else
          raise ArgumentError.new("Unknown RSA mode")
        end
      end

      def self.decrypt(rsa : LibCryptoJose::RSA, ciphertext : Bytes, mode : Symbol) : Bytes
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
          oaep256_op(rsa, ciphertext, false)
        else
          raise ArgumentError.new("Unknown RSA mode")
        end
      end

      private def self.oaep256_op(rsa : LibCryptoJose::RSA, input : Bytes, encrypt : Bool) : Bytes
        pkey = LibCryptoJose.EVP_PKEY_new
        raise "EVP_PKEY_new failed" if pkey.null?
        begin
          LibCryptoJose.EVP_PKEY_set1_RSA(pkey, rsa)
          ctx = LibCryptoJose.EVP_PKEY_CTX_new(pkey, Pointer(Void).null)
          raise "EVP_PKEY_CTX_new failed" if ctx.null?
          begin
            if encrypt
              raise "EVP_PKEY_encrypt_init failed" unless LibCryptoJose.EVP_PKEY_encrypt_init(ctx) == 1
            else
              raise "EVP_PKEY_decrypt_init failed" unless LibCryptoJose.EVP_PKEY_decrypt_init(ctx) == 1
            end
            raise "EVP_PKEY_CTX_ctrl failed (padding)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                                LibCryptoJose::EVP_PKEY_CTRL_RSA_PADDING, LibCryptoJose::RSA_PKCS1_OAEP_PADDING, Pointer(Void).null) > 0
            raise "EVP_PKEY_CTX_ctrl failed (oaep md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                                LibCryptoJose::EVP_PKEY_CTRL_RSA_OAEP_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
            raise "EVP_PKEY_CTX_ctrl failed (mgf1 md)" unless LibCryptoJose.EVP_PKEY_CTX_ctrl(ctx, LibCryptoJose::EVP_PKEY_RSA, -1,
                                                                LibCryptoJose::EVP_PKEY_CTRL_RSA_MGF1_MD, 0, LibCrypto.evp_sha256.as(Void*)) > 0
            outlen = LibC::SizeT.new(0)
            if encrypt
              LibCryptoJose.EVP_PKEY_encrypt(ctx, Pointer(UInt8).null, pointerof(outlen), input, input.size)
              out_buf = Bytes.new(outlen)
              raise "EVP_PKEY_encrypt failed" unless LibCryptoJose.EVP_PKEY_encrypt(ctx, out_buf, pointerof(outlen), input, input.size) == 1
            else
              LibCryptoJose.EVP_PKEY_decrypt(ctx, Pointer(UInt8).null, pointerof(outlen), input, input.size)
              out_buf = Bytes.new(outlen)
              raise "EVP_PKEY_decrypt failed" unless LibCryptoJose.EVP_PKEY_decrypt(ctx, out_buf, pointerof(outlen), input, input.size) == 1
            end
            out_buf[0, outlen.to_i]
          ensure
            LibCryptoJose.EVP_PKEY_CTX_free(ctx)
          end
        ensure
          LibCryptoJose.EVP_PKEY_free(pkey)
        end
      end
    end
  end
end
