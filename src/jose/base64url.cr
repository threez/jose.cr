module JOSE
  # Base64url encoding/decoding utilities (RFC 7515 §2).
  module Base64Url
    # Encodes *data* as a URL-safe base64 string without padding (RFC 7515 §2).
    def self.encode(data : Bytes) : String
      Base64.urlsafe_encode(data, padding: false)
    end

    # Decodes the URL-safe base64 string *str*, adding padding as required.
    def self.decode(str : String) : Bytes
      padded = str
      case str.size % 4
      when 2 then padded = str + "=="
      when 3 then padded = str + "="
      end
      Base64.decode(padded.tr("-_", "+/"))
    end
  end
end
