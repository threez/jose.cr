module JOSE
  module JWA
    # AES-GCM authenticated encryption (128 / 192 / 256-bit keys).
    # Uses raw LibCrypto/LibCryptoJose bindings because Crystal's OpenSSL::Cipher
    # does not expose auth_data= or auth_tag for GCM mode.
    module AES_GCM
      # Encrypts *plaintext* with *key* and *iv*, authenticating *aad*.
      #
      # *key* must be 16, 24, or 32 bytes (selects AES-128/192/256-GCM).
      # *iv* should be 12 bytes (96 bits) for GCM. *aad* is the additional
      # authenticated data (e.g. the base64url-encoded protected header in JWE).
      #
      # Returns `{ciphertext, tag}` where *tag* is a 16-byte authentication tag.
      def self.encrypt(key : Bytes, iv : Bytes, plaintext : Bytes, aad : Bytes) : {Bytes, Bytes}
        cipher = gcm_cipher(key.size)
        ctx = LibCrypto.evp_cipher_ctx_new
        raise "EVP_CIPHER_CTX_new failed" if ctx.null?
        begin
          # Set cipher type (no key/IV yet)
          LibCryptoJose.EVP_EncryptInit_ex(ctx, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null)
          # Set IV length
          LibCryptoJose.EVP_CIPHER_CTX_ctrl(ctx, LibCryptoJose::EVP_CTRL_AEAD_SET_IVLEN, iv.size, Pointer(Void).null)
          # Set key + IV
          LibCryptoJose.EVP_EncryptInit_ex(ctx, Pointer(Void).null, Pointer(Void).null, key, iv)
          # Feed AAD (null output signals AAD-only update)
          unless aad.empty?
            outl = 0
            LibCryptoJose.EVP_EncryptUpdate(ctx, Pointer(UInt8).null, pointerof(outl), aad, aad.size)
          end
          # Encrypt plaintext
          ct_buf = Bytes.new(plaintext.size + 16)
          outl = 0
          LibCryptoJose.EVP_EncryptUpdate(ctx, ct_buf, pointerof(outl), plaintext, plaintext.size)
          ct_len = outl
          LibCryptoJose.EVP_EncryptFinal_ex(ctx, ct_buf + ct_len, pointerof(outl))
          ct_len += outl
          # Get auth tag
          tag = Bytes.new(16)
          LibCryptoJose.EVP_CIPHER_CTX_ctrl(ctx, LibCryptoJose::EVP_CTRL_AEAD_GET_TAG, 16, tag.to_unsafe.as(Void*))
          {ct_buf[0, ct_len], tag}
        ensure
          LibCrypto.evp_cipher_ctx_free(ctx)
        end
      end

      # Decrypts *ciphertext* with *key*, *iv*, and *aad*, verifying *tag*.
      # Raises if authentication fails.
      def self.decrypt(key : Bytes, iv : Bytes, ciphertext : Bytes, tag : Bytes, aad : Bytes) : Bytes
        cipher = gcm_cipher(key.size)
        ctx = LibCrypto.evp_cipher_ctx_new
        raise "EVP_CIPHER_CTX_new failed" if ctx.null?
        begin
          LibCryptoJose.EVP_DecryptInit_ex(ctx, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null)
          LibCryptoJose.EVP_CIPHER_CTX_ctrl(ctx, LibCryptoJose::EVP_CTRL_AEAD_SET_IVLEN, iv.size, Pointer(Void).null)
          LibCryptoJose.EVP_DecryptInit_ex(ctx, Pointer(Void).null, Pointer(Void).null, key, iv)
          unless aad.empty?
            outl = 0
            LibCryptoJose.EVP_DecryptUpdate(ctx, Pointer(UInt8).null, pointerof(outl), aad, aad.size)
          end
          pt_buf = Bytes.new(ciphertext.size + 16)
          outl = 0
          LibCryptoJose.EVP_DecryptUpdate(ctx, pt_buf, pointerof(outl), ciphertext, ciphertext.size)
          pt_len = outl
          # Set expected tag before Final
          tag_copy = tag.dup
          LibCryptoJose.EVP_CIPHER_CTX_ctrl(ctx, LibCryptoJose::EVP_CTRL_AEAD_SET_TAG, tag_copy.size, tag_copy.to_unsafe.as(Void*))
          ret = LibCryptoJose.EVP_DecryptFinal_ex(ctx, pt_buf + pt_len, pointerof(outl))
          raise "AES-GCM tag verification failed" unless ret == 1
          pt_len += outl
          pt_buf[0, pt_len]
        ensure
          LibCrypto.evp_cipher_ctx_free(ctx)
        end
      end

      private def self.gcm_cipher(key_size : Int32) : LibCrypto::EVP_CIPHER
        case key_size
        when 16 then LibCryptoJose.EVP_aes_128_gcm
        when 24 then LibCryptoJose.EVP_aes_192_gcm
        when 32 then LibCryptoJose.EVP_aes_256_gcm
        else         raise ArgumentError.new("Unsupported AES-GCM key size: #{key_size}")
        end
      end
    end
  end
end
