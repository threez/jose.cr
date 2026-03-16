module JOSE
  # Wraps a compact JWS serialization; the three dot-separated parts are:
  # `protected_header.payload.signature`.
  struct SignedBinary
    # The raw compact JWS serialization (`header.payload.signature`).
    getter compact : String

    def initialize(@compact : String)
    end

    # Returns the decoded protected header without verifying the signature.
    def peek_protected : Hash(String, JSON::Any)
      JSON.parse(String.new(Base64Url.decode(parts[0]))).as_h
    end

    # Returns the decoded payload string without verifying the signature.
    def peek_payload : String
      header = JSON.parse(String.new(Base64Url.decode(parts[0]))).as_h
      header["b64"]?.try(&.as_bool) != false ? String.new(Base64Url.decode(parts[1])) : parts[1]
    end

    # Returns the raw signature bytes without verifying.
    def peek_signature : Bytes
      Base64Url.decode(parts[2])
    end

    private def parts : Array(String)
      @compact.split('.')
    end
  end
end
