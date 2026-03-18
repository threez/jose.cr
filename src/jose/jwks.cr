module JOSE
  # Represents a JSON Web Key Set (JWKS, RFC 7517 §5).
  #
  # A JWKS is an ordered collection of `JWK` objects serialised as
  # `{"keys": [...]}`.  It is the standard container for publishing public
  # keys (e.g. OIDC `/.well-known/jwks.json`) and for managing key rotation.
  class JWKS
    include Enumerable(JWK)

    getter keys : Array(JWK)

    # Constructs a `JWKS` from an ordered array of `JWK` objects.
    def initialize(@keys : Array(JWK))
    end

    # ── Constructors ─────────────────────────────────────────────────────────

    # Constructs a `JWKS` from a parsed JSON map.
    #
    # Unknown `kty` values are silently ignored (RFC 7517 §5: "SHOULD ignore
    # JWKs … with 'kty' values that are not understood").
    def self.from_map(map : Hash(String, JSON::Any)) : JWKS
      known_kty = %w[EC RSA oct OKP]
      raw_keys = map["keys"]?.try(&.as_a) || [] of JSON::Any
      jwks = raw_keys.compact_map do |entry|
        h = entry.as_h
        kty = h["kty"]?.try(&.as_s)
        next unless kty && known_kty.includes?(kty)
        JWK.from_map(h)
      end
      new(jwks)
    end

    # Parses *json* and returns the resulting `JWKS`.
    def self.from_binary(json : String) : JWKS
      from_map(JSON.parse(json).as_h)
    end

    # ── Serialisation ────────────────────────────────────────────────────────

    # Returns a JSON map of the form `{"keys" => [...]}`.
    def to_map : Hash(String, JSON::Any)
      JSON.parse({"keys" => @keys.map(&.to_map)}.to_json).as_h
    end

    # Serialises this key set to a compact JSON string.
    def to_binary : String
      to_map.to_json
    end

    # Returns the number of keys in the set.
    def size : Int32
      @keys.size
    end

    # ── Key access ───────────────────────────────────────────────────────────

    # Returns the `JWK` whose `kid` equals *kid*, or raises `KeyError`.
    def [](kid : String) : JWK
      self[kid]? || raise KeyError.new("No JWK with kid=#{kid.inspect}")
    end

    # Returns the `JWK` whose `kid` equals *kid*, or `nil`.
    def []?(kid : String) : JWK?
      @keys.find { |k| k["kid"]?.try(&.as_s) == kid }
    end

    # Yields each `JWK` in order.
    def each(& : JWK -> _)
      @keys.each { |k| yield k }
    end

    # ── Key set operations (immutable) ────────────────────────────────────────

    # Returns a new `JWKS` containing only public key material for every key.
    def to_public : JWKS
      JWKS.new(@keys.map(&.to_public))
    end

    # Returns a new `JWKS` with *jwk* appended.
    def add(jwk : JWK) : JWKS
      JWKS.new(@keys + [jwk])
    end

    # Returns a new `JWKS` with the key whose `kid` equals *kid* removed.
    # Returns an unchanged copy if no key matches.
    def remove(kid : String) : JWKS
      filter { |k| k["kid"]?.try(&.as_s) != kid }
    end

    # Returns a new `JWKS` that is the concatenation of this set and *other*.
    def merge(other : JWKS) : JWKS
      JWKS.new(@keys + other.keys)
    end

    # Returns a new `JWKS` containing only keys for which the block returns `true`.
    def filter(&block : JWK -> Bool) : JWKS
      JWKS.new(@keys.select(&block))
    end
  end
end
