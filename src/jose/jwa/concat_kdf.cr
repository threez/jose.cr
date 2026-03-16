module JOSE
  module JWA
    # Concat KDF (single-pass SHA-256) per RFC 7518 §4.6.2.
    # Supports optional apu/apv (PartyUInfo / PartyVInfo) parameters.
    module ConcatKDF
      # Derives a symmetric key from shared secret *z* using Concat KDF
      # (SHA-256, single-pass, RFC 7518 §4.6.2).
      #
      # Returns the first *key_bits*/8 bytes of the SHA-256 digest.
      # *algorithm* is the JWE `"alg"` string bound into the key derivation.
      # *apu* and *apv* are optional PartyUInfo / PartyVInfo byte strings.
      def self.derive(z : Bytes, algorithm : String, key_bits : Int32,
                      apu : Bytes = Bytes.empty, apv : Bytes = Bytes.empty) : Bytes
        hash_input = IO::Memory.new
        hash_input.write_bytes(1_u32, IO::ByteFormat::BigEndian)
        hash_input.write(z)
        hash_input.write(length_prefixed_bytes(algorithm.to_slice))
        hash_input.write(length_prefixed_bytes(apu))
        hash_input.write(length_prefixed_bytes(apv))
        hash_input.write_bytes(key_bits.to_u32, IO::ByteFormat::BigEndian)

        digest = OpenSSL::Digest.new("SHA256").update(hash_input.to_slice).final
        digest[0, key_bits // 8]
      end

      private def self.length_prefixed_bytes(data : Bytes) : Bytes
        io = IO::Memory.new(4 + data.size)
        io.write_bytes(data.size.to_u32, IO::ByteFormat::BigEndian)
        io.write(data) unless data.empty?
        io.to_slice
      end
    end
  end
end
