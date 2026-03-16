module JOSE
  module JWA
    # AES-CBC with HMAC authentication per RFC 7516 Appendix B.
    # key layout: mac_key (first half) ‖ enc_key (second half)
    # tag = HMAC-SHA(mac_key, aad_len_be64 ‖ aad ‖ iv ‖ ciphertext)[0, tag_len]
    module AES_CBC_HMAC
      # Encrypts *plaintext* with *key* and *iv*, authenticating *aad*.
      #
      # *key* is the composite key (MAC key ‖ ENC key): 32 bytes for
      # `A128CBC-HS256`, 48 for `A192CBC-HS384`, 64 for `A256CBC-HS512`.
      # *iv* must be 16 bytes (AES block size). *aad* is bound into the HMAC tag.
      #
      # Returns `{ciphertext, tag}` where *tag* is the truncated HMAC output.
      def self.encrypt(key : Bytes, iv : Bytes, plaintext : Bytes, aad : Bytes) : {Bytes, Bytes}
        mac_key, enc_key = split_key(key)
        bits = enc_key.size * 8

        cipher = OpenSSL::Cipher.new("aes-#{bits}-cbc")
        cipher.encrypt
        cipher.key = enc_key
        cipher.iv = iv
        ct = cipher.update(plaintext) + cipher.final # PKCS7 padding

        tag = compute_tag(mac_key, aad, iv, ct, tag_len_for(key))
        {ct, tag}
      end

      # Decrypts *ciphertext* and verifies the HMAC tag.
      # Raises `ArgumentError` on tag mismatch.
      def self.decrypt(key : Bytes, iv : Bytes, ciphertext : Bytes, tag : Bytes, aad : Bytes) : Bytes
        mac_key, enc_key = split_key(key)
        expected_tag = compute_tag(mac_key, aad, iv, ciphertext, tag_len_for(key))
        raise ArgumentError.new("AES-CBC-HMAC: authentication tag mismatch") unless constant_time_eq(tag, expected_tag)

        bits = enc_key.size * 8
        cipher = OpenSSL::Cipher.new("aes-#{bits}-cbc")
        cipher.decrypt
        cipher.key = enc_key
        cipher.iv = iv
        cipher.update(ciphertext) + cipher.final # strips PKCS7 padding
      end

      private def self.constant_time_eq(a : Bytes, b : Bytes) : Bool
        return false unless a.size == b.size
        result = 0_u8
        a.size.times { |i| result |= a[i] ^ b[i] }
        result == 0
      end

      private def self.split_key(key : Bytes) : {Bytes, Bytes}
        half = key.size // 2
        {key[0, half], key[half, half]}
      end

      private def self.tag_len_for(key : Bytes) : Int32
        # T_LEN = floor(HMAC_OUTPUT_LEN / 2) per RFC 7518 §5.2.2.1
        # A128CBC-HS256 (32-byte key, SHA-256) → 16
        # A192CBC-HS384 (48-byte key, SHA-384) → 24
        # A256CBC-HS512 (64-byte key, SHA-512) → 32
        key.size // 2
      end

      private def self.compute_tag(mac_key : Bytes, aad : Bytes, iv : Bytes,
                                   ct : Bytes, tag_len : Int32) : Bytes
        aad_len_bits = IO::Memory.new(8)
        aad_len_bits.write_bytes((aad.size.to_u64 * 8), IO::ByteFormat::BigEndian)

        mac_input = IO::Memory.new
        mac_input.write(aad)
        mac_input.write(iv)
        mac_input.write(ct)
        mac_input.write(aad_len_bits.to_slice)

        algo = case mac_key.size
               when 16 then OpenSSL::Algorithm::SHA256
               when 24 then OpenSSL::Algorithm::SHA384
               when 32 then OpenSSL::Algorithm::SHA512
               else         raise ArgumentError.new("Unsupported MAC key size #{mac_key.size}")
               end

        OpenSSL::HMAC.digest(algo, mac_key, mac_input.to_slice)[0, tag_len]
      end
    end
  end
end
