require "../spec_helper"

class MyJWT < JOSE::JWT
  claim role : String?
  claim permissions : Array(String)?
end

describe JOSE::JWT do
  claims = JSON.parse({"sub" => "alice", "iss" => "example.com"}.to_json).as_h

  # ── Constructors & serialisation ─────────────────────────────────────────

  describe ".from_binary / .from_map / #to_binary / #to_map" do
    it "round-trips via from_binary / to_binary" do
      json = claims.to_json
      jwt = JOSE::JWT.from_binary(json)
      jwt.to_binary.should eq(json)
    end

    it "round-trips via from_map / to_map" do
      jwt = JOSE::JWT.from_map(claims)
      jwt.to_map.should eq(claims)
    end
  end

  # ── Claim accessors ───────────────────────────────────────────────────────

  describe "#[] and #[]?" do
    it "returns the claim value with []" do
      jwt = JOSE::JWT.from_map(claims)
      jwt["sub"].as_s.should eq("alice")
    end

    it "raises KeyError for missing key with []" do
      jwt = JOSE::JWT.from_map(claims)
      expect_raises(KeyError) { jwt["missing"] }
    end

    it "returns nil for missing key with []?" do
      jwt = JOSE::JWT.from_map(claims)
      jwt["missing"]?.should be_nil
    end
  end

  # ── Sign / verify ─────────────────────────────────────────────────────────

  describe ".sign / .verify" do
    it "signs and verifies with HS256 (oct)" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, decoded, header = JOSE::JWT.verify(jwk, signed)
      valid.should be_true
      decoded["sub"].as_s.should eq("alice")
      header["typ"].as_s.should eq("JWT")
      header["alg"].as_s.should eq("HS256")
    end

    it "signs and verifies with ES256 (EC P-256)" do
      jwk = JOSE::JWK.from_map(generate_ec_jwk_map("P-256"))
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, decoded, _header = JOSE::JWT.verify(jwk, signed)
      valid.should be_true
      decoded["iss"].as_s.should eq("example.com")
    end

    it "signs and verifies with EdDSA (OKP Ed25519)" do
      jwk = JOSE::JWK.generate_key(JSON.parse({"kty" => "OKP", "crv" => "Ed25519"}.to_json).as_h)
      pub = jwk.to_public
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, decoded, header = JOSE::JWT.verify(pub, signed)
      valid.should be_true
      decoded["sub"].as_s.should eq("alice")
      header["alg"].as_s.should eq("EdDSA")
    end

    it "accepts a compact string as input to verify" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, decoded, _header = JOSE::JWT.verify(jwk, signed.compact)
      valid.should be_true
      decoded["sub"].as_s.should eq("alice")
    end

    it "sets typ=JWT in the protected header" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      _valid, _decoded, header = JOSE::JWT.verify(jwk, signed)
      header["typ"].as_s.should eq("JWT")
    end
  end

  # ── verify_strict ─────────────────────────────────────────────────────────

  describe ".verify_strict" do
    it "accepts the correct algorithm" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
      valid.should be_true
      decoded["sub"].as_s.should eq("alice")
    end

    it "rejects a disallowed algorithm" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["RS256", "ES256"], signed)
      valid.should be_false
    end
  end

  # ── Peek helpers ──────────────────────────────────────────────────────────

  describe ".peek_payload / .peek / .peek_protected" do
    it "peek_payload decodes claims without a key" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      peeked = JOSE::JWT.peek_payload(signed.compact)
      peeked["sub"].as_s.should eq("alice")
    end

    it "peek is an alias for peek_payload" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      JOSE::JWT.peek(signed.compact).to_map.should eq(
        JOSE::JWT.peek_payload(signed.compact).to_map
      )
    end

    it "peek_protected returns the header without a key" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      signed = JOSE::JWT.sign(jwk, jwt)
      header = JOSE::JWT.peek_protected(signed.compact)
      header["alg"].as_s.should eq("HS256")
      header["typ"].as_s.should eq("JWT")
    end
  end

  # ── Encrypt / decrypt ─────────────────────────────────────────────────────

  describe ".encrypt / .decrypt" do
    it "encrypts and decrypts with ECDH-ES (EC key pair)" do
      priv = JOSE::JWK.from_map(generate_ec_jwk_map("P-256"))
      pub = priv.to_public
      jwt = JOSE::JWT.from_map(claims)
      token = JOSE::JWT.encrypt(pub, jwt)
      decoded = JOSE::JWT.decrypt(priv, token)
      decoded["sub"].as_s.should eq("alice")
    end

    it "encrypts and decrypts with dir (oct key)" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.from_map(claims)
      overrides = {"alg" => JSON::Any.new("dir")}
      token = JOSE::JWT.encrypt(jwk, jwt, overrides)
      decoded = JOSE::JWT.decrypt(jwk, token)
      decoded["sub"].as_s.should eq("alice")
    end

    it "accepts a compact string as input to decrypt" do
      priv = JOSE::JWK.from_map(generate_ec_jwk_map("P-256"))
      pub = priv.to_public
      jwt = JOSE::JWT.from_map(claims)
      token = JOSE::JWT.encrypt(pub, jwt)
      decoded = JOSE::JWT.decrypt(priv, token.compact)
      decoded["iss"].as_s.should eq("example.com")
    end
  end

  # ── RFC 7519 Appendix A.1 fixed vector ────────────────────────────────────

  describe "RFC 7519 Appendix A.1" do
    it "peek_payload decodes claims without key" do
      token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
              ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
              ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      peeked = JOSE::JWT.peek_payload(token)
      peeked["iss"].as_s.should eq("joe")
      peeked["exp"].as_i64.should eq(1300819380)
    end

    it "verifies signed JWT with fixed vector" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}))
      token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
              ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
              ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      valid, decoded, header = JOSE::JWT.verify(jwk, token)
      valid.should be_true
      decoded["iss"].as_s.should eq("joe")
      header["alg"].as_s.should eq("HS256")
    end
  end

  # ── Time-claim helpers ─────────────────────────────────────────────────────

  describe "#expired? / #not_yet_valid? / #valid_at?" do
    it "expired? returns false when exp is not set" do
      jwt = JOSE::JWT.new
      jwt.expired?.should be_false
    end

    it "expired? returns false when exp is in the future" do
      jwt = JOSE::JWT.new
      jwt.exp = Time.unix(9_999_999_999_i64)
      jwt.expired?.should be_false
    end

    it "expired? returns true when exp is in the past" do
      jwt = JOSE::JWT.new
      jwt.exp = Time.unix(1_000_000_000_i64)
      jwt.expired?(now: Time.unix(2_000_000_000_i64)).should be_true
    end

    it "not_yet_valid? returns false when nbf is not set" do
      jwt = JOSE::JWT.new
      jwt.not_yet_valid?.should be_false
    end

    it "not_yet_valid? returns true when nbf is in the future" do
      jwt = JOSE::JWT.new
      jwt.nbf = Time.unix(9_999_999_999_i64)
      jwt.not_yet_valid?(now: Time.unix(1_000_000_000_i64)).should be_true
    end

    it "not_yet_valid? returns false when nbf is in the past" do
      jwt = JOSE::JWT.new
      jwt.nbf = Time.unix(1_000_000_000_i64)
      jwt.not_yet_valid?(now: Time.unix(2_000_000_000_i64)).should be_false
    end

    it "valid_at? returns true for token with future exp and past nbf" do
      now = Time.unix(1_500_000_000_i64)
      jwt = JOSE::JWT.new
      jwt.exp = Time.unix(2_000_000_000_i64)
      jwt.nbf = Time.unix(1_000_000_000_i64)
      jwt.valid_at?(now: now).should be_true
    end

    it "valid_at? returns false for expired token" do
      now = Time.unix(2_500_000_000_i64)
      jwt = JOSE::JWT.new
      jwt.exp = Time.unix(2_000_000_000_i64)
      jwt.valid_at?(now: now).should be_false
    end

    it "valid_at? returns false for token not yet valid" do
      now = Time.unix(500_000_000_i64)
      jwt = JOSE::JWT.new
      jwt.nbf = Time.unix(1_000_000_000_i64)
      jwt.valid_at?(now: now).should be_false
    end

    it "valid_at? returns true when neither exp nor nbf is set" do
      jwt = JOSE::JWT.new
      jwt.valid_at?.should be_true
    end
  end

  # ── claim macro — RFC 7519 registered claims ──────────────────────────────

  describe "claim macro — RFC 7519 registered claims" do
    describe "#iss / #sub / #jti" do
      it "returns nil when unset" do
        jwt = JOSE::JWT.new
        jwt.iss.should be_nil
        jwt.sub.should be_nil
        jwt.jti.should be_nil
      end

      it "round-trips string values" do
        jwt = JOSE::JWT.new
        jwt.iss = "example.com"
        jwt.sub = "alice"
        jwt.jti = "token-id-1"
        jwt.iss.should eq("example.com")
        jwt.sub.should eq("alice")
        jwt.jti.should eq("token-id-1")
      end

      it "nil setter deletes the key" do
        jwt = JOSE::JWT.new
        jwt.iss = "example.com"
        jwt.iss = nil
        jwt.fields.has_key?("iss").should be_false
        jwt.iss.should be_nil
      end

      it "reads from from_map" do
        jwt = JOSE::JWT.from_map({"iss" => JSON::Any.new("example.com"), "sub" => JSON::Any.new("bob")})
        jwt.iss.should eq("example.com")
        jwt.sub.should eq("bob")
      end
    end

    describe "#exp / #nbf / #iat" do
      it "returns nil when unset" do
        jwt = JOSE::JWT.new
        jwt.exp.should be_nil
        jwt.nbf.should be_nil
        jwt.iat.should be_nil
      end

      it "round-trips Time values (whole-second precision)" do
        now = Time.unix(Time.utc.to_unix) # truncate to whole seconds
        jwt = JOSE::JWT.new
        jwt.exp = now
        jwt.nbf = now - 10.seconds
        jwt.iat = now - 5.seconds
        jwt.exp.should eq(now)
        jwt.nbf.should eq(now - 10.seconds)
        jwt.iat.should eq(now - 5.seconds)
      end

      it "stores exp as int64 in @fields" do
        now = Time.unix(1700000000_i64)
        jwt = JOSE::JWT.new
        jwt.exp = now
        jwt.fields["exp"].as_i64.should eq(1700000000_i64)
      end

      it "nil setter deletes the key" do
        jwt = JOSE::JWT.new
        jwt.exp = Time.utc
        jwt.exp = nil
        jwt.fields.has_key?("exp").should be_false
      end

      it "reads exp from the RFC 7519 Appendix A.1 token" do
        token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
                ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
                ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        jwt = JOSE::JWT.peek_payload(token)
        jwt.exp.should eq(Time.unix(1300819380_i64))
        jwt.iss.should eq("joe")
      end
    end

    describe "#aud" do
      it "returns nil when unset" do
        jwt = JOSE::JWT.new
        jwt.aud.should be_nil
      end

      it "round-trips a single string" do
        jwt = JOSE::JWT.new
        jwt.aud = "api.example.com"
        jwt.aud.should eq("api.example.com")
      end

      it "round-trips a string array" do
        jwt = JOSE::JWT.new
        jwt.aud = ["api.example.com", "auth.example.com"]
        jwt.aud.should eq(["api.example.com", "auth.example.com"])
      end

      it "stores array as JSON array in @fields" do
        jwt = JOSE::JWT.new
        jwt.aud = ["a", "b"]
        jwt.fields["aud"].as_a.map(&.as_s).should eq(["a", "b"])
      end

      it "reads single aud from from_map" do
        jwt = JOSE::JWT.from_map({"aud" => JSON::Any.new("single")})
        jwt.aud.should eq("single")
      end

      it "reads array aud from from_map" do
        jwt = JOSE::JWT.from_map({"aud" => JSON::Any.new([JSON::Any.new("a"), JSON::Any.new("b")])})
        jwt.aud.should eq(["a", "b"])
      end

      it "nil setter deletes the key" do
        jwt = JOSE::JWT.new
        jwt.aud = "example.com"
        jwt.aud = nil
        jwt.fields.has_key?("aud").should be_false
      end
    end

    describe "sign/verify round-trip" do
      it "typed claims survive sign → verify_strict" do
        jwk = generate_oct_jwk(32)
        jwt = JOSE::JWT.new
        jwt.iss = "example.com"
        jwt.sub = "alice"
        jwt.exp = Time.unix(9999999999_i64)
        signed = JOSE::JWT.sign(jwk, jwt)
        valid, decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
        valid.should be_true
        decoded.iss.should eq("example.com")
        decoded.sub.should eq("alice")
        decoded.exp.should eq(Time.unix(9999999999_i64))
      end
    end
  end

  # ── registered claim aliases ──────────────────────────────────────────────

  describe "registered claim aliases" do
    it "issuer aliases iss" do
      jwt = JOSE::JWT.new
      jwt.issuer = "example.com"
      jwt.iss.should eq("example.com")
      jwt.issuer.should eq("example.com")
      jwt.issuer = nil
      jwt.iss.should be_nil
    end

    it "subject aliases sub" do
      jwt = JOSE::JWT.new
      jwt.subject = "alice"
      jwt.sub.should eq("alice")
      jwt.subject.should eq("alice")
    end

    it "audience aliases aud" do
      jwt = JOSE::JWT.new
      jwt.audience = ["api", "web"]
      jwt.aud.should eq(["api", "web"])
      jwt.audience.should eq(["api", "web"])
    end

    it "expires_at aliases exp" do
      jwt = JOSE::JWT.new
      t = Time.utc(2030, 1, 1)
      jwt.expires_at = t
      jwt.exp.should eq(t)
      jwt.expires_at.should eq(t)
    end

    it "not_before aliases nbf" do
      jwt = JOSE::JWT.new
      t = Time.utc(2025, 6, 1)
      jwt.not_before = t
      jwt.nbf.should eq(t)
      jwt.not_before.should eq(t)
    end

    it "issued_at aliases iat" do
      jwt = JOSE::JWT.new
      t = Time.utc(2025, 1, 1)
      jwt.issued_at = t
      jwt.iat.should eq(t)
      jwt.issued_at.should eq(t)
    end

    it "jwt_id aliases jti" do
      jwt = JOSE::JWT.new
      jwt.jwt_id = "abc-123"
      jwt.jti.should eq("abc-123")
      jwt.jwt_id.should eq("abc-123")
    end
  end

  # ── claim macro — subclassing ─────────────────────────────────────────────

  describe "claim macro — subclassing" do
    it "custom claims are nil before assignment" do
      tok = MyJWT.new
      tok.role.should be_nil
      tok.permissions.should be_nil
    end

    it "String claim round-trips" do
      tok = MyJWT.new
      tok.role = "admin"
      tok.role.should eq("admin")
      tok.role = nil
      tok.role.should be_nil
      tok.fields.has_key?("role").should be_false
    end

    it "Array(String) claim round-trips" do
      tok = MyJWT.new
      tok.permissions = ["read", "write"]
      tok.permissions.should eq(["read", "write"])
      tok.permissions = nil
      tok.permissions.should be_nil
      tok.fields.has_key?("permissions").should be_false
    end

    it "inherited RFC 7519 claims work on subclass" do
      tok = MyJWT.new
      tok.sub = "bob"
      tok.iss = "myapp"
      tok.sub.should eq("bob")
      tok.iss.should eq("myapp")
    end

    it "from_map on subclass returns subclass with all claims" do
      map = {
        "sub"         => JSON::Any.new("alice"),
        "role"        => JSON::Any.new("editor"),
        "permissions" => JSON::Any.new([JSON::Any.new("read")]),
      }
      tok = MyJWT.from_map(map)
      tok.sub.should eq("alice")
      tok.role.should eq("editor")
      tok.permissions.should eq(["read"])
    end

    it "full sign/verify with custom claims via from_map cast" do
      jwk = generate_oct_jwk(32)
      tok = MyJWT.new
      tok.sub = "alice"
      tok.role = "admin"
      tok.permissions = ["read", "write"]
      tok.exp = Time.unix(9999999999_i64)
      signed = JOSE::JWT.sign(jwk, tok)
      valid, decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
      valid.should be_true
      my_jwt = MyJWT.from_map(decoded.to_map)
      my_jwt.sub.should eq("alice")
      my_jwt.role.should eq("admin")
      my_jwt.permissions.should eq(["read", "write"])
      my_jwt.exp.should eq(Time.unix(9999999999_i64))
    end
  end

  # ── RFC 8725 (verify_strict claim validation) ─────────────────────────────

  describe "RFC 8725 (verify_strict claim validation)" do
    it "rejects an expired token (exp in the past)" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.exp = Time.utc - 1.second
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
      valid.should be_false
    end

    it "rejects a token with nbf in the future" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.nbf = Time.utc + 1.hour
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
      valid.should be_false
    end

    it "skips time checks when validate_claims: false" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.exp = Time.utc - 1.second
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        validate_claims: false)
      valid.should be_true
    end

    it "accepts matching iss" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.iss = "example.com"
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        iss: "example.com")
      valid.should be_true
    end

    it "rejects mismatched iss" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.iss = "other.com"
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        iss: "example.com")
      valid.should be_false
    end

    it "rejects missing iss when iss check requested" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        iss: "example.com")
      valid.should be_false
    end

    it "accepts aud when token aud matches single expected string" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.aud = "api"
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        aud: "api")
      valid.should be_true
    end

    it "accepts aud when token aud array contains expected value" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.aud = ["api", "admin"]
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        aud: "admin")
      valid.should be_true
    end

    it "rejects mismatched aud" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.aud = "other"
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        aud: "api")
      valid.should be_false
    end

    it "accepts typ: JWT (set automatically by JWT.sign)" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        typ: "JWT")
      valid.should be_true
    end

    it "rejects typ mismatch" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        typ: "at+JWT")
      valid.should be_false
    end

    it "passes all validations combined for a valid token" do
      jwk = generate_oct_jwk(32)
      jwt = JOSE::JWT.new
      jwt.iss = "example.com"
      jwt.aud = "api"
      jwt.exp = Time.utc + 1.hour
      jwt.nbf = Time.utc - 1.second
      signed = JOSE::JWT.sign(jwk, jwt)
      valid, _decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
        iss: "example.com",
        aud: "api",
        typ: "JWT")
      valid.should be_true
    end
  end
end
