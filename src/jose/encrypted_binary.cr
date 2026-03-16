module JOSE
  # Wraps a compact JWE (five base64url parts joined by dots)
  # and provides inspection methods without decryption.
  # The five dot-separated parts are: `protected_header.encrypted_key.iv.ciphertext.tag`.
  struct EncryptedBinary
    # The raw compact JWE serialization (`header.key.iv.ciphertext.tag`).
    getter compact : String

    def initialize(@compact : String)
    end

    def to_s(io : IO) : Nil
      io << @compact
    end

    # Returns the decoded protected header map without decrypting.
    def peek_protected : Hash(String, JSON::Any)
      JWE.peek_protected(@compact)
    end

    # Returns the wrapped CEK bytes without decrypting.
    def peek_encrypted_key : Bytes
      JWE.peek_encrypted_key(@compact)
    end

    # Returns the initialization vector bytes without decrypting.
    def peek_iv : Bytes
      JWE.peek_iv(@compact)
    end

    # Returns the ciphertext bytes without decrypting.
    def peek_ciphertext : Bytes
      JWE.peek_ciphertext(@compact)
    end

    # Returns the authentication tag bytes without decrypting.
    def peek_tag : Bytes
      JWE.peek_tag(@compact)
    end
  end
end
