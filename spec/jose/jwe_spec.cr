require "../spec_helper"

describe JOSE::JWE do
  it "peek_protected returns the decoded header" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    compact = jwk.block_encrypt("hello").compact
    header = JOSE::JWE.peek_protected(compact)
    header["alg"].as_s.should eq("ECDH-ES+A256KW")
    header["enc"].as_s.should eq("A256GCM")
  end

  it "peek_iv returns 12 bytes" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    JOSE::JWE.peek_iv(jwk.block_encrypt("hello").compact).size.should eq(12)
  end

  it "peek_tag returns 16 bytes" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    JOSE::JWE.peek_tag(jwk.block_encrypt("hello").compact).size.should eq(16)
  end

  it "peek_ciphertext length matches plaintext length" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    plain = "hello world"
    JOSE::JWE.peek_ciphertext(jwk.block_encrypt(plain).compact).size.should eq(plain.bytesize)
  end

  it "round-trips ECDH-ES+A256KW / A256GCM (regression)" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    plain = "my-secret-token"
    encrypted = jwk.block_encrypt(plain)
    decrypted = jwk.block_decrypt(encrypted)
    decrypted.should eq(plain)
  end

  it "round-trips ECDH-ES / A128GCM" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    overrides = JSON.parse({"alg" => "ECDH-ES", "enc" => "A128GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "hello ecdh-es", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("hello ecdh-es")
  end

  it "round-trips A256KW / A256CBC-HS512" do
    jwk = generate_oct_jwk(32)
    overrides = JSON.parse({"alg" => "A256KW", "enc" => "A256CBC-HS512"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "cbc-hmac test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("cbc-hmac test")
  end

  it "round-trips A128KW / A128CBC-HS256" do
    jwk = generate_oct_jwk(16)
    overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128CBC-HS256"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "small key", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("small key")
  end

  it "round-trips dir / A192GCM" do
    jwk = generate_oct_jwk(24)
    overrides = JSON.parse({"alg" => "dir", "enc" => "A192GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "direct key", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("direct key")
  end

  it "round-trips RSA-OAEP / A256GCM" do
    jwk = generate_rsa_jwk
    overrides = JSON.parse({"alg" => "RSA-OAEP", "enc" => "A256GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "rsa oaep test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("rsa oaep test")
  end

  it "round-trips RSA-OAEP-256 / A256GCM" do
    jwk = generate_rsa_jwk
    overrides = JSON.parse({"alg" => "RSA-OAEP-256", "enc" => "A256GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "rsa oaep-256 test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("rsa oaep-256 test")
  end

  it "round-trips RSA1_5 / A128GCM" do
    jwk = generate_rsa_jwk
    overrides = JSON.parse({"alg" => "RSA1_5", "enc" => "A128GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "rsa1_5 test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("rsa1_5 test")
  end

  it "round-trips ECDH-ES+A128KW / A192GCM" do
    jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
    overrides = JSON.parse({"alg" => "ECDH-ES+A128KW", "enc" => "A192GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk, "128kw test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("128kw test")
  end

  it "round-trips RSA-OAEP / A256GCM with 4096-bit key" do
    jwk = JOSE::JWK.from_binary(
      %q({"kty":"RSA","kid":"samwise.gamgee@hobbiton.example","use":"enc","alg":"RSA-OAEP",) +
      %q("n":"wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHI) +
      %q(lh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg) +
      %q(71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGs) +
      %q(MwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg) +
      %q(1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kN) +
      %q(GcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpV) +
      %q(jvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDx) +
      %q(DQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE",) +
      %q("e":"AQAB",) +
      %q("d":"n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCIwg91oCt0JvxPcpmq) +
      %q(zaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRx) +
      %q(UOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuIm) +
      %q(YcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihL) +
      %q(xnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1J) +
      %q(WxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu2) +
      %q(8gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_Ku) +
      %q(BG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c9WsWgRzI-K8gE",) +
      %q("p":"7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRkOvbb01kYVuLFmxIkCDtpi-zLC) +
      %q(YAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J96) +
      %q(1Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzN) +
      %q(SCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ",) +
      %q("q":"zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHi) +
      %q(l1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwf) +
      %q(QTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIx) +
      %q(JS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q",) +
      %q("dp":"19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1erdHdms_Ef67HsONNv5A60JaR) +
      %q(7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjX) +
      %q(oTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0) +
      %q(LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ",) +
      %q("dq":"S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-1jjwELKDjck8kOBl5UvohK1oD) +
      %q(fSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa0) +
      %q(8pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODS) +
      %q(z9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ",) +
      %q("qi":"FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxglZn-omAY5CnCe4KdrnjFOT5YUZ) +
      %q(E7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31) +
      %q(XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89) +
      %q(QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA"})
    )
    overrides = JSON.parse({"alg" => "RSA-OAEP", "enc" => "A256GCM"}.to_json).as_h
    encrypted = JOSE::JWE.block_encrypt(jwk.to_public, "4096-bit rsa-oaep test", overrides)
    decrypted = JOSE::JWE.block_decrypt(jwk, encrypted)
    decrypted.should eq("4096-bit rsa-oaep test")
  end

  describe "JWE JSON Serialization" do
    it "json_encrypt produces flattened JSON with required fields" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM"}.to_json).as_h
      json = JOSE::JWE.json_encrypt(jwk, "hello json jwe", overrides)
      parsed = JSON.parse(json).as_h
      parsed.has_key?("protected").should be_true
      parsed.has_key?("encrypted_key").should be_true
      parsed.has_key?("iv").should be_true
      parsed.has_key?("ciphertext").should be_true
      parsed.has_key?("tag").should be_true
      parsed.has_key?("recipients").should be_false
    end

    it "round-trips flattened JSON (A128KW / A128GCM)" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM"}.to_json).as_h
      json = JOSE::JWE.json_encrypt(jwk, "hello json jwe", overrides)
      JOSE::JWE.json_decrypt(jwk, json).should eq("hello json jwe")
    end

    it "round-trips flattened JSON with AAD" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM"}.to_json).as_h
      aad = "extra authenticated data".to_slice
      json = JOSE::JWE.json_encrypt(jwk, "aad payload", overrides, aad)
      parsed = JSON.parse(json).as_h
      parsed.has_key?("aad").should be_true
      JOSE::JWE.json_decrypt(jwk, json).should eq("aad payload")
    end

    it "round-trips flattened JSON with ECDH-ES+A256KW" do
      jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
      json = JOSE::JWE.json_encrypt(jwk, "ecdh json test")
      JOSE::JWE.json_decrypt(jwk, json).should eq("ecdh json test")
    end

    it "json_decrypt handles general form (recipients array)" do
      jwk = generate_oct_jwk(16)
      # Build a general-form JSON from a compact token — protected header stays intact
      # so the AAD matches; we just wrap it in the general-form recipients array.
      compact = JOSE::JWE.block_encrypt(jwk, "general form test").compact
      parts = compact.split('.')
      general = {
        "protected"  => JSON::Any.new(parts[0]),
        "recipients" => JSON::Any.new([JSON::Any.new({"encrypted_key" => JSON::Any.new(parts[1])})]),
        "iv"         => JSON::Any.new(parts[2]),
        "ciphertext" => JSON::Any.new(parts[3]),
        "tag"        => JSON::Any.new(parts[4]),
      }.to_json
      JOSE::JWE.json_decrypt(jwk, general).should eq("general form test")
    end

    it "json_decrypt rejects wrong key" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM"}.to_json).as_h
      json = JOSE::JWE.json_encrypt(jwk, "secret", overrides)
      wrong = generate_oct_jwk(16)
      expect_raises(ArgumentError, /No matching recipient/) do
        JOSE::JWE.json_decrypt(wrong, json)
      end
    end
  end

  describe "DEFLATE compression (zip: DEF)" do
    it "round-trips A128KW / A128GCM with zip: DEF" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM", "zip" => "DEF"}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt(jwk, "compress me please", overrides)
      header = JOSE::JWE.peek_protected(encrypted.compact)
      header["zip"].as_s.should eq("DEF")
      JOSE::JWE.block_decrypt(jwk, encrypted).should eq("compress me please")
    end

    it "round-trips ECDH-ES+A256KW / A256GCM with zip: DEF" do
      jwk = JOSE::JWK.from_map(generate_ec_jwk_map)
      overrides = JSON.parse({"zip" => "DEF"}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt(jwk, "compressed ecdh payload", overrides)
      JOSE::JWE.block_decrypt(jwk, encrypted).should eq("compressed ecdh payload")
    end

    it "compressed ciphertext is smaller for repetitive content" do
      jwk = generate_oct_jwk(32)
      plain = "aaaa" * 200
      plain_enc = JOSE::JWE.block_encrypt(jwk, plain)
      zip_overrides = JSON.parse({"zip" => "DEF"}.to_json).as_h
      zip_enc = JOSE::JWE.block_encrypt(jwk, plain, zip_overrides)
      JOSE::JWE.peek_ciphertext(zip_enc.compact).size.should be < JOSE::JWE.peek_ciphertext(plain_enc.compact).size
    end
  end

  describe "AES-GCM Key Wrap" do
    it "round-trips A128GCMKW / A128GCM" do
      jwk = generate_oct_jwk(16)
      overrides = JSON.parse({"alg" => "A128GCMKW", "enc" => "A128GCM"}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt(jwk, "hello gcmkw-128", overrides)
      header = JOSE::JWE.peek_protected(encrypted.compact)
      header["alg"].as_s.should eq("A128GCMKW")
      header.has_key?("iv").should be_true
      header.has_key?("tag").should be_true
      JOSE::JWE.block_decrypt(jwk, encrypted).should eq("hello gcmkw-128")
    end

    it "round-trips A192GCMKW / A192GCM" do
      jwk = generate_oct_jwk(24)
      overrides = JSON.parse({"alg" => "A192GCMKW", "enc" => "A192GCM"}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt(jwk, "hello gcmkw-192", overrides)
      JOSE::JWE.block_decrypt(jwk, encrypted).should eq("hello gcmkw-192")
    end

    it "round-trips A256GCMKW / A128CBC-HS256" do
      jwk = generate_oct_jwk(32)
      overrides = JSON.parse({"alg" => "A256GCMKW", "enc" => "A128CBC-HS256"}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt(jwk, "hello gcmkw-256", overrides)
      JOSE::JWE.block_decrypt(jwk, encrypted).should eq("hello gcmkw-256")
    end
  end

  describe "PBES2 password-based key wrap" do
    it "round-trips PBES2-HS256+A128KW / A256GCM" do
      overrides = JSON.parse({"alg" => "PBES2-HS256+A128KW", "enc" => "A256GCM", "p2c" => 1000}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt("s3cr3t", "hello pbes2-256", overrides)
      decrypted = JOSE::JWE.block_decrypt("s3cr3t", encrypted)
      decrypted.should eq("hello pbes2-256")
    end

    it "round-trips PBES2-HS384+A192KW / A192GCM" do
      overrides = JSON.parse({"alg" => "PBES2-HS384+A192KW", "enc" => "A192GCM", "p2c" => 1000}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt("p@ssw0rd", "hello pbes2-384", overrides)
      decrypted = JOSE::JWE.block_decrypt("p@ssw0rd", encrypted)
      decrypted.should eq("hello pbes2-384")
    end

    it "round-trips PBES2-HS512+A256KW / A128CBC-HS256" do
      overrides = JSON.parse({"alg" => "PBES2-HS512+A256KW", "enc" => "A128CBC-HS256", "p2c" => 1000}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt("correct horse battery staple", "hello pbes2-512", overrides)
      decrypted = JOSE::JWE.block_decrypt("correct horse battery staple", encrypted)
      decrypted.should eq("hello pbes2-512")
    end

    it "wrong password fails to decrypt" do
      overrides = JSON.parse({"alg" => "PBES2-HS512+A256KW", "enc" => "A256GCM", "p2c" => 1000}.to_json).as_h
      encrypted = JOSE::JWE.block_encrypt("right", "secret", overrides)
      expect_raises(Exception) do
        JOSE::JWE.block_decrypt("wrong", encrypted)
      end
    end
  end

  describe "RFC 7516 Appendix A.1" do
    it "decrypts RSA-OAEP + A256GCM token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA",) +
        %q("n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",) +
        %q("e":"AQAB",) +
        %q("d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",) +
        %q("p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",) +
        %q("q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",) +
        %q("dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",) +
        %q("dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",) +
        %q("qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"})
      )
      token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ" \
              ".OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg" \
              ".48V1_ALb6US04U3b" \
              ".5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A" \
              ".XFBoMYUZodetZdvTiFvSkQ"
      decrypted = JOSE::JWE.block_decrypt(jwk, token)
      decrypted.should eq("The true sign of intelligence is not knowledge but imagination.")
    end
  end
end
