module JOSE
  module JWA
    # AES Key Wrap (RFC 3394) — wrap and unwrap a key using AES-ECB.
    module AES_KW
      # The RFC 3394 default IV (`0xA6` × 8) used to verify unwrap integrity.
      DEFAULT_IV = Bytes[0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]

      # Wraps *plaintext* using *kek* (Key Encryption Key) per RFC 3394.
      # Returns the wrapped key bytes.
      def self.wrap(kek : Bytes, plaintext : Bytes) : Bytes
        raise ArgumentError.new("plaintext must be a multiple of 8 bytes") unless plaintext.size % 8 == 0

        n = plaintext.size // 8
        a = DEFAULT_IV.dup
        r = Array(Bytes).new(n) { |i| plaintext[i * 8, 8].dup }

        6.times do |j|
          n.times do |i|
            input = IO::Memory.new(16)
            input.write(a)
            input.write(r[i])

            b = aes_ecb_op(kek, input.to_slice, true)

            t = (n * j + i + 1).to_u64
            a = b[0, 8].dup
            t_bytes = IO::Memory.new(8)
            t_bytes.write_bytes(t, IO::ByteFormat::BigEndian)
            8.times { |k| a[k] ^= t_bytes.to_slice[k] }
            r[i] = b[8, 8].dup
          end
        end

        result = IO::Memory.new(8 + n * 8)
        result.write(a)
        r.each { |block| result.write(block) }
        result.to_slice
      end

      # Unwraps *ciphertext* using *kek*.
      # Returns the original key bytes. Raises `ArgumentError` if the IV
      # integrity check fails.
      def self.unwrap(kek : Bytes, ciphertext : Bytes) : Bytes
        raise ArgumentError.new("ciphertext must be a multiple of 8 bytes") unless ciphertext.size % 8 == 0
        raise ArgumentError.new("ciphertext too short") if ciphertext.size < 16

        n = ciphertext.size // 8 - 1
        a = ciphertext[0, 8].dup
        r = Array(Bytes).new(n) { |i| ciphertext[(i + 1) * 8, 8].dup }

        5.downto(0) do |j|
          n.downto(1) do |i|
            t = (n * j + i).to_u64
            t_bytes = IO::Memory.new(8)
            t_bytes.write_bytes(t, IO::ByteFormat::BigEndian)
            a_xor = a.dup
            8.times { |k| a_xor[k] ^= t_bytes.to_slice[k] }

            input = IO::Memory.new(16)
            input.write(a_xor)
            input.write(r[i - 1])

            b = aes_ecb_op(kek, input.to_slice, false)
            a = b[0, 8].dup
            r[i - 1] = b[8, 8].dup
          end
        end

        raise ArgumentError.new("AES Key Unwrap: IV mismatch") unless a == DEFAULT_IV

        result = IO::Memory.new(n * 8)
        r.each { |block| result.write(block) }
        result.to_slice
      end

      private def self.aes_ecb_op(key : Bytes, data : Bytes, encrypt : Bool) : Bytes
        cipher = OpenSSL::Cipher.new("aes-#{key.size * 8}-ecb")
        encrypt ? cipher.encrypt : cipher.decrypt
        cipher.padding = false
        cipher.key = key
        cipher.update(data) + cipher.final
      end
    end
  end
end
