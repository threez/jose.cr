require "../spec_helper"

# RFC 7517 Appendix A.2 — Example Private Keys (EC + RSA)
RFC_A2_JSON = %q({"keys":[
  {"kty":"EC","crv":"P-256",
   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
   "use":"enc","kid":"1"},
  {"kty":"RSA",
   "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   "e":"AQAB",
   "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
   "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
   "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
   "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
   "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
   "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
   "alg":"RS256","kid":"2011-04-29"}
]})

# RFC 7517 Appendix A.1 — Example Public Keys (EC + RSA)
RFC_A1_JSON = %q({"keys":[
  {"kty":"EC","crv":"P-256",
   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   "use":"enc","kid":"1"},
  {"kty":"RSA",
   "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   "e":"AQAB","alg":"RS256","kid":"2011-04-29"}
]})

# RFC 7517 Appendix A.3 — Example Symmetric Keys (oct)
RFC_A3_JSON = %q({"keys":[
  {"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"},
  {"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow","kid":"HMAC key used in JWS spec Appendix A.1 example"}
]})

describe JOSE::JWKS do
  describe "from_map / from_binary / to_map / to_binary" do
    it "round-trips RFC A.1 two-key set" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks.size.should eq(2)

      # Keys wrapper is preserved
      map = jwks.to_map
      map.has_key?("keys").should be_true
      map["keys"].as_a.size.should eq(2)

      # round-trip through binary
      jwks2 = JOSE::JWKS.from_binary(jwks.to_binary)
      jwks2.size.should eq(2)
      jwks2["1"]["kty"].as_s.should eq("EC")
      jwks2["2011-04-29"]["kty"].as_s.should eq("RSA")
    end

    it "from_map builds from a parsed hash" do
      map = JSON.parse(RFC_A1_JSON).as_h
      jwks = JOSE::JWKS.from_map(map)
      jwks.size.should eq(2)
    end
  end

  describe "size" do
    it "returns the correct count" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks.size.should eq(2)
    end

    it "returns 0 for an empty set" do
      jwks = JOSE::JWKS.new([] of JOSE::JWK)
      jwks.size.should eq(0)
    end
  end

  describe "[] / []?" do
    it "looks up a key by kid" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks["1"]["kty"].as_s.should eq("EC")
      jwks["2011-04-29"]["kty"].as_s.should eq("RSA")
    end

    it "[]? returns nil for unknown kid" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks["missing"]?.should be_nil
    end

    it "[] raises KeyError for unknown kid" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      expect_raises(KeyError) { jwks["no-such-kid"] }
    end
  end

  describe "each" do
    it "iterates over all keys" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      count = 0
      jwks.each { |_k| count += 1 }
      count.should eq(2)
    end
  end

  describe "to_public" do
    it "strips private fields from every key" do
      k1 = ec_jwk_with_kid("sig")
      k2 = ec_jwk_with_kid("enc")
      jwks = JOSE::JWKS.new([k1, k2])

      # source keys are private
      k1.private?.should be_true
      k2.private?.should be_true

      public_jwks = jwks.to_public
      public_jwks.size.should eq(2)
      public_jwks.keys.each do |k|
        k.public?.should be_true
      end

      # originals untouched
      k1.private?.should be_true
    end
  end

  describe "add" do
    it "returns a new JWKS with the extra key; original unchanged" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      extra = ec_jwk_with_kid("new")
      bigger = jwks.add(extra)

      jwks.size.should eq(2)
      bigger.size.should eq(3)
      bigger["new"]["kty"].as_s.should eq("EC")
    end
  end

  describe "remove" do
    it "returns a new JWKS without the named key; original unchanged" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON) # kids: "1", "2011-04-29"
      smaller = jwks.remove("1")

      jwks.size.should eq(2)
      smaller.size.should eq(1)
      smaller["1"]?.should be_nil
      smaller["2011-04-29"]["kty"].as_s.should eq("RSA")
    end

    it "returns an unchanged copy when kid is not present" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      same = jwks.remove("nonexistent")
      same.size.should eq(2)
    end
  end

  describe "merge" do
    it "concatenates two sets" do
      jwks1 = JOSE::JWKS.new([ec_jwk_with_kid("a"), ec_jwk_with_kid("b")])
      jwks2 = JOSE::JWKS.new([ec_jwk_with_kid("c")])
      merged = jwks1.merge(jwks2)

      merged.size.should eq(3)
      merged["a"]["kty"].as_s.should eq("EC")
      merged["c"]["kty"].as_s.should eq("EC")
    end
  end

  describe "filter" do
    it "selects only matching keys" do
      k_ec = ec_jwk_with_kid("sig")
      k_oct = generate_oct_jwk(32).with(kid: "sym")
      jwks = JOSE::JWKS.new([k_ec, k_oct])

      ec_only = jwks.filter { |k| k.kty == "EC" }
      ec_only.size.should eq(1)
      ec_only.keys.first.kty.should eq("EC")
    end

    it "returns empty JWKS when nothing matches" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      none = jwks.filter { |k| k.kty == "OKP" }
      none.size.should eq(0)
    end
  end

  describe "Enumerable" do
    it "map collects key types" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      types = jwks.map(&.kty)
      types.should eq(["EC", "RSA"])
    end

    it "any? returns true when predicate matches" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks.any?(&.kty.==("EC")).should be_true
      jwks.any?(&.kty.==("OKP")).should be_false
    end

    it "count returns number matching predicate" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      jwks.count(&.kty.==("EC")).should eq(1)
      jwks.count(&.kty.==("RSA")).should eq(1)
    end

    it "find returns a matching key" do
      jwks = JOSE::JWKS.from_binary(RFC_A1_JSON)
      found = jwks.find { |k| k.kty == "RSA" }
      found.should_not be_nil
      found.try(&.kty).should eq("RSA")
    end
  end

  describe "RFC A.3 symmetric keys" do
    it "round-trips oct key set" do
      jwks = JOSE::JWKS.from_binary(RFC_A3_JSON)
      jwks.size.should eq(2)
      jwks.keys.each(&.kty.should(eq("oct")))

      jwks2 = JOSE::JWKS.from_binary(jwks.to_binary)
      jwks2.size.should eq(2)
    end
  end

  describe "unknown kty skipping" do
    it "silently ignores entries with unknown kty" do
      json = %q({"keys":[
        {"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","kid":"k1"},
        {"kty":"unknown","foo":"bar","kid":"k2"}
      ]})
      jwks = JOSE::JWKS.from_binary(json)
      jwks.size.should eq(1)
      jwks["k1"]["kty"].as_s.should eq("EC")
    end
  end

  describe "RFC 7517 Appendix A.2 private key set" do
    it "parses two private keys; to_public makes all public" do
      jwks = JOSE::JWKS.from_binary(RFC_A2_JSON)
      jwks.size.should eq(2)
      jwks.keys.each(&.private?.should(be_true))

      public_jwks = jwks.to_public
      public_jwks.size.should eq(2)
      public_jwks.keys.each(&.public?.should(be_true))
    end
  end
end
