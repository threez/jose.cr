module JOSE
  # JWT (JSON Web Token) compact representation of claims (RFC 7519).
  #
  # Tokens are backed by a `Hash(String, JSON::Any)` and can be signed (JWS)
  # or encrypted (JWE). The seven RFC 7519 registered claims (`iss`, `sub`,
  # `aud`, `exp`, `nbf`, `iat`, `jti`) are available as typed accessors.
  # Use the `claim` macro to define additional typed claims in a subclass:
  #
  # ```
  # require "jose"
  #
  # class MyJWT < JOSE::JWT
  #   claim role : String?
  # end
  #
  # jwk = JOSE::JWK.generate_key_oct
  #
  # tok = MyJWT.new
  # tok.sub = "alice"
  # tok.role = "admin"
  # tok.exp = Time.utc + 1.hour
  #
  # signed = JOSE::JWT.sign(jwk, tok)
  # valid, decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
  # my_jwt = MyJWT.from_map(decoded.to_map)
  # my_jwt.sub  # => "alice"
  # my_jwt.role # => "admin"
  # ```
  class JWT
    # The claims map backing this token.
    getter fields : Hash(String, JSON::Any)

    # Constructs a `JWT` pre-populated with *fields*.
    def initialize(@fields : Hash(String, JSON::Any))
    end

    # Constructs an empty `JWT` with no claims set.
    def initialize
      @fields = {} of String => JSON::Any
    end

    # Defines a typed getter/setter pair for a JWT claim.
    #
    # The claim name becomes the JSON key. Supported types: `String`, `String?`,
    # `String | Array(String) | Nil`, `Time?`, `Int64?`, `Bool?`,
    # `Array(String)?`, `Array(JSON::Any)?`, and `JSON::Any?`.
    #
    # An optional *long_name* adds human-readable aliases (e.g. `issuer` for `iss`).
    #
    # ```
    # class MyJWT < JOSE::JWT
    #   claim role : String?
    #   claim exp_detail : Time?, long_name: expires_at_detail
    # end
    # ```
    macro claim(decl, long_name = nil)
      {% name = decl.var %}
      {% raw_type = decl.type %}
      {% key = name.stringify %}

      {% if raw_type.is_a?(Union) %}
        {% non_nil = raw_type.types.reject { |type_node| type_node.stringify == "Nil" } %}
        {% nullable = true %}
      {% else %}
        {% non_nil = [raw_type] %}
        {% nullable = false %}
      {% end %}

      {% cores = non_nil.map(&.stringify) %}

      {% if cores.includes?("String") && cores.includes?("Array(String)") %}
        def {{name}} : String | Array(String) | Nil
          raw = @fields[{{key}}]?
          return nil if raw.nil?
          raw.as_a? ? raw.as_a.map(&.as_s) : raw.as_s
        end

        def {{name}}=(value : String | Array(String) | Nil)
          if value.nil?
            @fields.delete({{key}})
          elsif value.is_a?(Array)
            @fields[{{key}}] = JSON::Any.new(value.map { |s| JSON::Any.new(s) })
          else
            @fields[{{key}}] = JSON::Any.new(value.as(String))
          end
        end

      {% elsif cores[0] == "Time" %}
        def {{name}} : {{raw_type}}
          raw = @fields[{{key}}]?
          {% if nullable %}return nil if raw.nil?{% end %}
          Time.unix(raw.not_nil!.as_i64)
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!.to_unix)
        end

      {% elsif cores[0] == "Int64" %}
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?.try(&.as_i64){% else %}@fields[{{key}}].as_i64{% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!)
        end

      {% elsif cores[0] == "Bool" %}
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?.try(&.as_bool){% else %}@fields[{{key}}].as_bool{% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!)
        end

      {% elsif cores[0] == "Array(String)" %}
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?.try(&.as_a.map(&.as_s)){% else %}@fields[{{key}}].as_a.map(&.as_s){% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!.map { |s| JSON::Any.new(s) })
        end

      {% elsif cores[0] == "Array(JSON::Any)" %}
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?.try(&.as_a){% else %}@fields[{{key}}].as_a{% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!)
        end

      {% elsif cores[0] == "JSON::Any" %}
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?{% else %}@fields[{{key}}]{% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = value.not_nil!
        end

      {% else %}
        # String (default fallthrough)
        def {{name}} : {{raw_type}}
          {% if nullable %}@fields[{{key}}]?.try(&.as_s){% else %}@fields[{{key}}].as_s{% end %}
        end

        def {{name}}=(value : {{raw_type}})
          {% if nullable %}
            if value.nil?; @fields.delete({{key}}); return; end
          {% end %}
          @fields[{{key}}] = JSON::Any.new(value.not_nil!)
        end
      {% end %}

      {% if long_name %}
        # Long-form alias for `{{name}}`.
        def {{long_name.id}} : {{raw_type}}
          {{name}}
        end

        # Long-form alias for `{{name}}=`.
        def {{long_name.id}}=(v : {{raw_type}})
          self.{{name}} = v
        end
      {% end %}
    end

    # ── RFC 7519 Registered Claims ───────────────────────────────────────────

    # Issuer identifier (RFC 7519 §4.1.1). Long-form alias: `issuer`.
    claim iss : String?, long_name: issuer

    # Subject identifier (RFC 7519 §4.1.2). Long-form alias: `subject`.
    claim sub : String?, long_name: subject

    # Audience (RFC 7519 §4.1.3). Long-form alias: `audience`.
    claim aud : String | Array(String) | Nil, long_name: audience

    # Expiration time as UTC `Time` (RFC 7519 §4.1.4). Long-form alias: `expires_at`.
    claim exp : Time?, long_name: expires_at

    # Not-before time as UTC `Time` (RFC 7519 §4.1.5). Long-form alias: `not_before`.
    claim nbf : Time?, long_name: not_before

    # Issued-at time as UTC `Time` (RFC 7519 §4.1.6). Long-form alias: `issued_at`.
    claim iat : Time?, long_name: issued_at

    # Unique JWT identifier (RFC 7519 §4.1.7). Long-form alias: `jwt_id`.
    claim jti : String?, long_name: jwt_id

    # ── Time-claim helpers ────────────────────────────────────────────────────

    # Returns `true` if `exp` is set and is in the past relative to *now*.
    # Does NOT verify the signature — call `verify_strict` for that.
    def expired?(now : Time = Time.utc) : Bool
      exp_time = self.exp
      return false if exp_time.nil?
      now >= exp_time
    end

    # Returns `true` if `nbf` is set and has not yet been reached relative to *now*.
    def not_yet_valid?(now : Time = Time.utc) : Bool
      nbf_time = self.nbf
      return false if nbf_time.nil?
      now < nbf_time
    end

    # Returns `true` if the token is currently valid: not expired and nbf has passed.
    # Does NOT verify the signature — call `verify_strict` for that.
    def valid_at?(now : Time = Time.utc) : Bool
      !expired?(now) && !not_yet_valid?(now)
    end

    # ── Constructors ─────────────────────────────────────────────────────────

    # Parses a JSON string and returns a `JWT`.
    def self.from_binary(json : String) : self
      new(JSON.parse(json).as_h)
    end

    # Wraps an existing claims map in a `JWT`.
    def self.from_map(map : Hash(String, JSON::Any)) : self
      new(map)
    end

    # ── Serialisation ────────────────────────────────────────────────────────

    # Serializes the claims to a compact JSON string.
    def to_binary : String
      @fields.to_json
    end

    # Returns the underlying claims map.
    def to_map : Hash(String, JSON::Any)
      @fields
    end

    # Returns the claim for *key*, raising `KeyError` when absent.
    def [](key : String) : JSON::Any
      @fields[key]
    end

    # Returns the claim for *key*, or `nil` when absent.
    def []?(key : String) : JSON::Any?
      @fields[key]?
    end

    # ── Signing ──────────────────────────────────────────────────────────────

    # Signs *jwt* with *jwk* and returns a compact `SignedBinary`.
    #
    # The `"typ"` header is set to `"JWT"` unless *header_overrides* provides
    # a different value. The signing algorithm is inferred from the key type
    # when not present in *header_overrides*.
    def self.sign(jwk : JWK, jwt : JWT,
                  header_overrides : Hash(String, JSON::Any)? = nil) : SignedBinary
      overrides = {"typ" => JSON::Any.new("JWT")}
      header_overrides.try &.each { |k, v| overrides[k] = v }
      JWS.sign(jwk, jwt.to_binary, overrides)
    end

    # Verifies a compact JWS carrying JWT claims.
    #
    # Returns `{valid, jwt, protected_header}`. *valid* is `true` when the
    # signature is correct. The JWT is decoded regardless of validity.
    def self.verify(jwk : JWK,
                    signed : String | SignedBinary) : {Bool, JWT, Hash(String, JSON::Any)}
      compact = signed.is_a?(SignedBinary) ? signed.compact : signed
      valid, payload = JWS.verify(jwk, compact)
      jwt = from_binary(payload)
      header = JWS.peek_protected(compact)
      {valid, jwt, header}
    end

    # Like `verify` but enforces RFC 8725 best-current-practices on top of the
    # cryptographic signature check.
    #
    # **Always checked:**
    # - `"alg"` header must appear in *allowed_algs* (algorithm-confusion guard).
    #
    # **Keyword parameters (all optional, off by default except `validate_claims`):**
    # - *iss* — expected issuer; token `iss` claim must match exactly (§3.8).
    # - *aud* — expected audience; token must include at least one of the given
    #   values (§3.9). Accepts a single string or an array.
    # - *typ* — expected `"typ"` header value, e.g. `"JWT"` or `"at+JWT"` (§3.11).
    # - *validate_claims* — when `true` (default) the token must not be expired
    #   and its `nbf` must have been reached (§3.3). Pass `false` to skip.
    #
    # Returns `{false, jwt, header}` whenever any check fails, even if the
    # cryptographic signature itself is valid.
    def self.verify_strict(jwk : JWK, allowed_algs : Array(String),
                           signed : String | SignedBinary, *,
                           iss : String? = nil,
                           aud : String | Array(String) | Nil = nil,
                           typ : String? = nil,
                           validate_claims : Bool = true) : {Bool, JWT, Hash(String, JSON::Any)}
      valid, jwt, header = verify(jwk, signed)

      # §3.1 — algorithm allowlist
      alg = header["alg"]?.try(&.as_s)
      valid = false unless alg && allowed_algs.includes?(alg)

      # §3.11 — explicit typing
      if typ
        valid = false unless header["typ"]?.try(&.as_s) == typ
      end

      # §3.3 — time-claim validation (exp / nbf)
      if validate_claims
        valid = false if jwt.expired?
        valid = false if jwt.not_yet_valid?
      end

      # §3.8 — issuer
      if iss
        valid = false unless jwt.iss == iss
      end

      # §3.9 — audience
      valid = false if aud && !aud_match?(jwt.aud, aud)

      {valid, jwt, header}
    end

    # ── Peek (no verification) ────────────────────────────────────────────────

    # Decodes the payload of *compact* as a `JWT` without verifying the
    # signature.
    def self.peek_payload(compact : String) : JWT
      from_binary(JWS.peek_payload(compact))
    end

    # Alias for `peek_payload`.
    def self.peek(compact : String) : JWT
      peek_payload(compact)
    end

    # Decodes the protected header of *compact* without verifying.
    def self.peek_protected(compact : String) : Hash(String, JSON::Any)
      JWS.peek_protected(compact)
    end

    # ── Encryption ───────────────────────────────────────────────────────────

    # Encrypts *jwt* for *jwk* and returns a compact `EncryptedBinary`.
    #
    # The `"typ"` header is set to `"JWT"` unless *header_overrides* overrides
    # it. The key-wrap and content-encryption algorithms are inferred from the
    # key type when not present in *header_overrides*.
    def self.encrypt(jwk : JWK, jwt : JWT,
                     header_overrides : Hash(String, JSON::Any)? = nil) : EncryptedBinary
      overrides = {"typ" => JSON::Any.new("JWT")}
      header_overrides.try &.each { |k, v| overrides[k] = v }
      JWE.block_encrypt(jwk, jwt.to_binary, overrides)
    end

    # Decrypts a compact JWE and returns the contained `JWT`.
    def self.decrypt(jwk : JWK,
                     encrypted : String | EncryptedBinary) : JWT
      plain = JWE.block_decrypt(jwk, encrypted)
      from_binary(plain)
    end

    # ── Private helpers ──────────────────────────────────────────────────────

    # Returns `true` when *jwt_aud* contains at least one value from *expected*.
    private def self.aud_match?(jwt_aud : String | Array(String) | Nil,
                                expected : String | Array(String)) : Bool
      expected_arr = expected.is_a?(Array) ? expected : [expected]
      token_arr = jwt_aud.is_a?(String) ? [jwt_aud.as(String)] : (jwt_aud || [] of String)
      expected_arr.any? { |expected_item| token_arr.includes?(expected_item) }
    end
  end
end
