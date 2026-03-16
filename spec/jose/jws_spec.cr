require "../spec_helper"

describe JOSE::JWS do
  it "HS256 sign + verify round-trip" do
    jwk = generate_oct_jwk(32)
    signed = JOSE::JWS.sign(jwk, "hello hmac")
    signed.compact.split(".").size.should eq(3)
    signed.peek_protected["alg"].as_s.should eq("HS256")
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("hello hmac")
  end

  it "HS256 verify rejects tampered payload" do
    jwk = generate_oct_jwk(32)
    signed = JOSE::JWS.sign(jwk, "original")
    parts = signed.compact.split(".")
    tampered = "#{parts[0]}.#{JOSE::Base64Url.encode("tampered".to_slice)}.#{parts[2]}"
    valid, _ = JOSE::JWS.verify(jwk, tampered)
    valid.should be_false
  end

  it "ES256 sign + verify round-trip" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    signed = JOSE::JWS.sign(jwk, "hello ecdsa")
    signed.peek_protected["alg"].as_s.should eq("ES256")
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("hello ecdsa")
  end

  it "ES256 verify with public key only" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    signed = JOSE::JWS.sign(jwk, "verify with public")
    valid, payload = JOSE::JWS.verify(jwk.to_public, signed)
    valid.should be_true
    payload.should eq("verify with public")
  end

  it "ES384 sign + verify round-trip" do
    params = JSON.parse({"kty" => "EC", "crv" => "P-384"}.to_json).as_h
    jwk = JOSE::JWK.generate_key(params)
    overrides = JSON.parse({"alg" => "ES384"}.to_json).as_h
    signed = JOSE::JWS.sign(jwk, "p384 test", overrides)
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("p384 test")
  end

  it "RS256 sign + verify round-trip" do
    jwk = generate_rsa_jwk
    overrides = JSON.parse({"alg" => "RS256"}.to_json).as_h
    signed = JOSE::JWS.sign(jwk, "hello rsa", overrides)
    signed.peek_protected["alg"].as_s.should eq("RS256")
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("hello rsa")
  end

  it "PS256 sign + verify round-trip" do
    jwk = generate_rsa_jwk
    overrides = JSON.parse({"alg" => "PS256"}.to_json).as_h
    signed = JOSE::JWS.sign(jwk, "hello pss", overrides)
    signed.peek_protected["alg"].as_s.should eq("PS256")
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("hello pss")
  end

  it "EdDSA sign + verify round-trip" do
    params = JSON.parse({"kty" => "OKP", "crv" => "Ed25519"}.to_json).as_h
    jwk = JOSE::JWK.generate_key(params)
    signed = JOSE::JWS.sign(jwk, "hello ed25519")
    signed.peek_protected["alg"].as_s.should eq("EdDSA")
    valid, payload = JOSE::JWS.verify(jwk, signed)
    valid.should be_true
    payload.should eq("hello ed25519")
  end

  it "JWK#sign and #verify delegates to JWS" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    signed = jwk.sign("test payload")
    valid, payload = jwk.verify(signed)
    valid.should be_true
    payload.should eq("test payload")
  end

  it "HS256 sign + verify with detached content" do
    jwk = generate_oct_jwk(32)
    payload = "hello detached"
    signed = JOSE::JWS.sign(jwk, payload)
    parts = signed.compact.split(".")
    detached_compact = "#{parts[0]}..#{parts[2]}"
    valid, returned = JOSE::JWS.verify(jwk, detached_compact, detached: payload)
    valid.should be_true
    returned.should eq(payload)
  end

  it "HS256 detached verify rejects wrong detached content" do
    jwk = generate_oct_jwk(32)
    signed = JOSE::JWS.sign(jwk, "correct payload")
    parts = signed.compact.split(".")
    detached_compact = "#{parts[0]}..#{parts[2]}"
    valid, _ = JOSE::JWS.verify(jwk, detached_compact, detached: "wrong payload")
    valid.should be_false
  end

  describe "JWS JSON Serialization (RFC 7515 §7.2)" do
    it "sign_json + verify_json round-trip (flattened, default protected header)" do
      jwk = generate_oct_jwk(32)
      token = JOSE::JWS.sign_json(jwk, "hello json")
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should eq("hello json")
      parsed = JSON.parse(token).as_h
      parsed.has_key?("protected").should be_true
      parsed.has_key?("signatures").should be_false
    end

    it "sign_json + verify_json with alg in unprotected (no protected header)" do
      jwk = generate_oct_jwk(32)
      unprotected = JSON.parse({"alg" => "HS256"}.to_json).as_h
      token = JOSE::JWS.sign_json(jwk, "unprotected alg", unprotected: unprotected)
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should eq("unprotected alg")
      parsed = JSON.parse(token).as_h
      parsed.has_key?("protected").should be_false
      parsed["header"].as_h["alg"].as_s.should eq("HS256")
    end

    it "sign_json + verify_json with split protected/unprotected headers" do
      jwk = generate_oct_jwk(32)
      unprotected = JSON.parse({"kid" => "my-key"}.to_json).as_h
      token = JOSE::JWS.sign_json(jwk, "split test", unprotected: unprotected)
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should eq("split test")
      parsed = JSON.parse(token).as_h
      parsed["header"].as_h["kid"].as_s.should eq("my-key")
      protected_h = JSON.parse(String.new(JOSE::Base64Url.decode(parsed["protected"].as_s))).as_h
      protected_h["alg"].as_s.should eq("HS256")
      protected_h.has_key?("kid").should be_false
    end

    it "verify_json rejects tampered signature" do
      jwk = generate_oct_jwk(32)
      token = JOSE::JWS.sign_json(jwk, "original")
      parsed = JSON.parse(token).as_h.dup
      parsed["signature"] = JSON::Any.new("aW52YWxpZHNpZ25hdHVyZQ")
      valid, _ = JOSE::JWS.verify_json(jwk, parsed.to_json)
      valid.should be_false
    end

    it "verify_json handles general form and returns true for matching key" do
      jwk1 = generate_oct_jwk(32)
      jwk2 = generate_oct_jwk(32)
      # Build a two-signature general JSON manually
      tok1 = JSON.parse(JOSE::JWS.sign_json(jwk1, "multi")).as_h
      tok2 = JSON.parse(JOSE::JWS.sign_json(jwk2, "multi")).as_h
      general = {
        "payload"    => tok1["payload"],
        "signatures" => JSON::Any.new([
          JSON::Any.new({"protected" => tok1["protected"], "signature" => tok1["signature"]}),
          JSON::Any.new({"protected" => tok2["protected"], "signature" => tok2["signature"]}),
        ] of JSON::Any),
      }.to_json
      valid1, payload1 = JOSE::JWS.verify_json(jwk1, general)
      valid1.should be_true
      payload1.should eq("multi")
      valid2, _ = JOSE::JWS.verify_json(jwk2, general)
      valid2.should be_true
      wrong = generate_oct_jwk(32)
      valid_wrong, _ = JOSE::JWS.verify_json(wrong, general)
      valid_wrong.should be_false
    end
  end

  describe "Nested JWS inside JWE" do
    it "sign-then-compact-encrypt + decrypt-then-verify round-trip" do
      signing_jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
      enc_jwk = generate_oct_jwk(16)
      payload = %({"sub":"alice","iss":"example.com"})

      compact_jws = JOSE::JWS.sign(signing_jwk, payload).compact
      jwe = JOSE::JWE.block_encrypt(enc_jwk, compact_jws)
      recovered_jws = JOSE::JWE.block_decrypt(enc_jwk, jwe)
      valid, recovered_payload = JOSE::JWS.verify(signing_jwk.to_public, recovered_jws)
      valid.should be_true
      recovered_payload.should eq(payload)
    end

    it "sign-then-json-encrypt + json-decrypt-then-verify round-trip" do
      signing_jwk = generate_rsa_jwk
      enc_jwk = generate_rsa_jwk
      overrides = JSON.parse({"alg" => "RSA-OAEP", "enc" => "A128GCM", "cty" => "JWT"}.to_json).as_h
      payload = %({"sub":"bob","iss":"example.com"})

      compact_jws = JOSE::JWS.sign(signing_jwk, payload).compact
      json_jwe = JOSE::JWE.json_encrypt(enc_jwk, compact_jws, overrides)
      recovered_jws = JOSE::JWE.json_decrypt(enc_jwk, json_jwe)
      valid, recovered_payload = JOSE::JWS.verify(signing_jwk.to_public, recovered_jws)
      valid.should be_true
      recovered_payload.should eq(payload)
    end
  end

  describe "RFC 7797 (b64=false Unencoded Payload)" do
    it "compact round-trip with b64=false" do
      jwk = generate_oct_jwk(32)
      plain_text = "hello unencoded"
      overrides = {"b64" => JSON::Any.new(false)}
      signed = JOSE::JWS.sign(jwk, plain_text, overrides)
      valid, payload = JOSE::JWS.verify(jwk, signed)
      valid.should be_true
      payload.should eq(plain_text)
    end

    it "auto-injects crit=[b64] when b64=false" do
      jwk = generate_oct_jwk(32)
      overrides = {"b64" => JSON::Any.new(false)}
      signed = JOSE::JWS.sign(jwk, "test", overrides)
      crit = signed.peek_protected["crit"].as_a.map(&.as_s)
      crit.should contain("b64")
    end

    it "peek_payload returns raw unencoded payload when b64=false" do
      jwk = generate_oct_jwk(32)
      plain_text = "raw payload"
      overrides = {"b64" => JSON::Any.new(false)}
      signed = JOSE::JWS.sign(jwk, plain_text, overrides)
      signed.peek_payload.should eq(plain_text)
    end

    it "verify rejects tampered payload with b64=false" do
      jwk = generate_oct_jwk(32)
      overrides = {"b64" => JSON::Any.new(false)}
      signed = JOSE::JWS.sign(jwk, "original", overrides)
      parts = signed.compact.split(".")
      tampered = "#{parts[0]}.tampered.#{parts[2]}"
      valid, _ = JOSE::JWS.verify(jwk, tampered)
      valid.should be_false
    end

    it "raises ArgumentError when payload contains '.' with b64=false" do
      jwk = generate_oct_jwk(32)
      overrides = {"b64" => JSON::Any.new(false)}
      expect_raises(ArgumentError, /must not contain/) do
        JOSE::JWS.sign(jwk, "a.b", overrides)
      end
    end

    it "JSON serialization round-trip with b64=false" do
      jwk = generate_oct_jwk(32)
      plain_text = "$.02"
      overrides = {"alg" => JSON::Any.new("HS256"), "b64" => JSON::Any.new(false)}
      token = JOSE::JWS.sign_json(jwk, plain_text, protected_overrides: overrides)
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should eq(plain_text)
    end

    it "does not duplicate b64 in crit when caller already provides it" do
      jwk = generate_oct_jwk(32)
      overrides = {
        "b64"  => JSON::Any.new(false),
        "crit" => JSON::Any.new([JSON::Any.new("custom"), JSON::Any.new("b64")] of JSON::Any),
      }
      signed = JOSE::JWS.sign(jwk, "test", overrides)
      crit = signed.peek_protected["crit"].as_a.map(&.as_s)
      crit.count("b64").should eq(1)
      crit.should contain("custom")
    end

    it "verifies RFC 7797 Appendix B vector (HS256, payload=$.02)" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}))
      # Protected: {"alg":"HS256","b64":false,"crit":["b64"]}
      # Payload: $.02 (raw, b64=false)
      # Signing input: eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.$.02
      token = %q({"payload":"$.02","protected":"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19","header":{"alg":"HS256"},"signature":"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"})
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should eq("$.02")
    end
  end

  describe "RFC 7515 Appendix A.1" do
    it "verifies HS256 token with fixed vector" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}))
      token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" \
              ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" \
              ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      valid, payload = JOSE::JWS.verify(jwk, token)
      valid.should be_true
      claims = JSON.parse(payload)
      claims["iss"].as_s.should eq("joe")
    end
  end
end
