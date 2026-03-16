require "../spec_helper"

describe JOSE::JWK do
  it "constructs from_map and exposes fields" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    jwk["kty"].as_s.should eq("EC")
    jwk.kty.should eq("EC")
  end

  it "constructs from_binary" do
    map = generate_ec_jwk_map
    jwk = JOSE::JWK.from_binary(map.to_json)
    jwk["kty"].as_s.should eq("EC")
  end

  it "round-trips to_map / to_binary" do
    map = generate_ec_jwk_map
    jwk = JOSE::JWK.from_map(map)
    jwk.to_map.should eq(map)
    JOSE::JWK.from_binary(jwk.to_binary).to_map.should eq(map)
  end

  it "reports private? / public? correctly for EC" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    jwk.private?.should be_true
    jwk.public?.should be_false
    pub = jwk.to_public
    pub.public?.should be_true
    pub.private?.should be_false
    pub["d"]?.should be_nil
  end

  it "to_public strips private fields" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    pub = jwk.to_public
    pub.map.has_key?("d").should be_false
    pub.map.has_key?("x").should be_true
  end

  it "generates EC P-384 key" do
    params = JSON.parse({"kty" => "EC", "crv" => "P-384"}.to_json).as_h
    jwk = JOSE::JWK.generate_key(params)
    jwk.kty.should eq("EC")
    jwk["crv"].as_s.should eq("P-384")
    jwk.private?.should be_true
  end

  it "generates RSA key" do
    jwk = generate_rsa_jwk
    jwk.kty.should eq("RSA")
    jwk.private?.should be_true
    jwk["n"].as_s.size.should be > 0
  end

  it "generates oct key" do
    jwk = generate_oct_jwk(32)
    jwk.kty.should eq("oct")
    JOSE::Base64Url.decode(jwk["k"].as_s).size.should eq(32)
  end

  it "generates OKP Ed25519 key" do
    params = JSON.parse({"kty" => "OKP", "crv" => "Ed25519"}.to_json).as_h
    jwk = JOSE::JWK.generate_key(params)
    jwk.kty.should eq("OKP")
    jwk["crv"].as_s.should eq("Ed25519")
    jwk.private?.should be_true
    JOSE::Base64Url.decode(jwk["x"].as_s).size.should eq(32)
    JOSE::Base64Url.decode(jwk["d"].as_s).size.should eq(32)
  end

  it "generate_key_ec defaults to P-256 and accepts crv override" do
    jwk = JOSE::JWK.generate_key_ec
    jwk.kty.should eq("EC")
    jwk["crv"].as_s.should eq("P-256")
    jwk.private?.should be_true
    jwk2 = JOSE::JWK.generate_key_ec(crv: "P-384")
    jwk2["crv"].as_s.should eq("P-384")
  end

  it "generate_key_rsa defaults to 2048 bits" do
    jwk = JOSE::JWK.generate_key_rsa
    jwk.kty.should eq("RSA")
    jwk.private?.should be_true
  end

  it "generate_key_oct accepts size override" do
    jwk = JOSE::JWK.generate_key_oct(size: 16)
    jwk.kty.should eq("oct")
    JOSE::Base64Url.decode(jwk["k"].as_s).size.should eq(16)
  end

  it "generate_key_okp defaults to Ed25519" do
    jwk = JOSE::JWK.generate_key_okp
    jwk.kty.should eq("OKP")
    jwk["crv"].as_s.should eq("Ed25519")
    jwk.private?.should be_true
  end

  it "round-trips EC PEM" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    pem = jwk.to_pem
    pem.should contain("BEGIN EC PRIVATE KEY")
    jwk2 = JOSE::JWK.from_pem(pem)
    jwk2.kty.should eq("EC")
    jwk2["crv"].as_s.should eq("P-256")
    jwk2["x"].as_s.should eq(jwk["x"].as_s)
    jwk2["y"].as_s.should eq(jwk["y"].as_s)
  end

  it "round-trips RSA PEM" do
    jwk = generate_rsa_jwk
    pem = jwk.to_pem
    pem.should contain("BEGIN RSA PRIVATE KEY")
    jwk2 = JOSE::JWK.from_pem(pem)
    jwk2.kty.should eq("RSA")
    jwk2["n"].as_s.should eq(jwk["n"].as_s)
  end

  it "encrypts plaintext with block_encrypt (ECDH-ES+A256KW / A256GCM)" do
    jwk = ec_jwk_with_kid("k1")
    encrypted = jwk.block_encrypt("my-secret-token")
    encrypted.compact.split(".").size.should eq(5)
    header = encrypted.peek_protected
    header["alg"].as_s.should eq("ECDH-ES+A256KW")
    header["enc"].as_s.should eq("A256GCM")
    header["kid"].as_s.should eq("k1")
    header["epk"]["kty"].as_s.should eq("EC")
    header["epk"]["crv"].as_s.should eq("P-256")
  end

  it "produces different ciphertexts for same plaintext" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    a = jwk.block_encrypt("same-input")
    b = jwk.block_encrypt("same-input")
    a.compact.should_not eq(b.compact)
  end

  it "supports URI prefix" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    token = "ionos+jose://" + jwk.block_encrypt("my-secret-token").compact
    token.starts_with?("ionos+jose://").should be_true
    token.sub("ionos+jose://", "").split(".").size.should eq(5)
  end

  describe "structural equality" do
    it "== returns true for JWKs with identical parameters" do
      jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
      jwk2 = JOSE::JWK.from_binary(jwk.to_binary)
      jwk.should eq(jwk2)
    end

    it "== returns false for different keys" do
      jwk1 = JOSE::JWK.generate_key_ec
      jwk2 = JOSE::JWK.generate_key_ec
      jwk1.should_not eq(jwk2)
    end
  end

  describe "#with" do
    it "returns a new JWK with the given fields merged in" do
      base = JOSE::JWK.generate_key_ec
      tagged = base.with(kid: "sig")
      tagged["kid"].as_s.should eq("sig")
      base["kid"]?.should be_nil
    end

    it "preserves all existing fields" do
      base = JOSE::JWK.generate_key_ec
      tagged = base.with(kid: "sig")
      tagged["kty"].as_s.should eq("EC")
      tagged["x"].as_s.should eq(base["x"].as_s)
    end

    it "overwrites an existing field" do
      base = JOSE::JWK.generate_key_ec.with(kid: "old")
      updated = base.with(kid: "new")
      updated["kid"].as_s.should eq("new")
      base["kid"].as_s.should eq("old")
    end

    it "merges multiple fields at once" do
      jwk = JOSE::JWK.generate_key_ec.with(kid: "sig", use: "sig", alg: "ES256")
      jwk["kid"].as_s.should eq("sig")
      jwk["use"].as_s.should eq("sig")
      jwk["alg"].as_s.should eq("ES256")
    end

    it "is chainable" do
      jwk = JOSE::JWK.generate_key_ec.with(kid: "sig").with(use: "sig")
      jwk["kid"].as_s.should eq("sig")
      jwk["use"].as_s.should eq("sig")
    end
  end

  describe ".from_map with keyword overrides" do
    it "merges string overrides without manual boxing" do
      base = JOSE::JWK.generate_key_ec
      tagged = JOSE::JWK.from_map(base.map, kid: "sig")
      tagged["kid"].as_s.should eq("sig")
      tagged["kty"].as_s.should eq("EC")
    end

    it "does not mutate the source map" do
      base = JOSE::JWK.generate_key_ec
      original_size = base.map.size
      JOSE::JWK.from_map(base.map, kid: "sig")
      base.map.size.should eq(original_size)
      base["kid"]?.should be_nil
    end
  end

  describe "RSA minimum key size" do
    it "generate_key raises for RSA < 2048 bits" do
      params = JSON.parse({"kty" => "RSA", "bits" => 1024}.to_json).as_h
      expect_raises(ArgumentError, /2048/) { JOSE::JWK.generate_key(params) }
    end

    it "generate_key_rsa raises for bits < 2048" do
      expect_raises(ArgumentError, /2048/) { JOSE::JWK.generate_key_rsa(bits: 1024) }
    end
  end

  describe "RFC 7517 Appendix A" do
    it "parses §A.1 EC P-256 public key" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}))
      jwk.kty.should eq("EC")
      jwk.public?.should be_true
      jwk.private?.should be_false
      jwk["x"].as_s.should eq("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
      jwk["y"].as_s.should eq("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
    end

    it "parses §A.2 EC P-256 private key" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}))
      jwk.private?.should be_true
      jwk["d"].as_s.should eq("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
      pub = jwk.to_public
      pub.public?.should be_true
      pub["d"]?.should be_nil
    end

    it "parses §A.1 RSA public key" do
      jwk = JOSE::JWK.from_binary(%q({"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}))
      jwk.kty.should eq("RSA")
      jwk.public?.should be_true
      jwk.private?.should be_false
      jwk["n"].as_s.should eq("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
      jwk["e"].as_s.should eq("AQAB")
    end

    it "parses §A.2 RSA private key" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA",) +
        %q("n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",) +
        %q("e":"AQAB",) +
        %q("d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",) +
        %q("p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",) +
        %q("q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",) +
        %q("dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",) +
        %q("dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",) +
        %q("qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",) +
        %q("alg":"RS256","kid":"2011-04-29"})
      )
      jwk.private?.should be_true
      jwk["d"].as_s.size.should be > 0
      pub = jwk.to_public
      pub.public?.should be_true
      pub["p"]?.should be_nil
      pub["q"]?.should be_nil
      pub["dp"]?.should be_nil
      pub["dq"]?.should be_nil
      pub["qi"]?.should be_nil
    end
  end
end
