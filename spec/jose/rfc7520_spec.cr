require "../spec_helper"

# RFC 7520 "Examples of Protecting Content Using JSON Object Signing and
# Encryption (JOSE)" — interoperability test vectors.
#
# Active tests:  15  (6 JWK + 4 JWS + 5 JWE)
# Pending:       12  (algorithm gaps + JSON-only serializations)
#
# Source: https://www.rfc-editor.org/rfc/rfc7520
# Cookbook JSON: https://github.com/ietf-jose/cookbook

describe "RFC 7520" do
  # ── §3 Key Examples ─────────────────────────────────────────────────────────

  describe "§3 Key Examples" do
    it "§3.1 parses EC P-521 public key" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",) +
        %q("x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",) +
        %q("y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"})
      )
      jwk.kty.should eq("EC")
      jwk["crv"].as_s.should eq("P-521")
      jwk.public?.should be_true
      jwk.private?.should be_false
      jwk["x"].as_s.should eq(
        "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt"
      )
    end

    it "§3.2 parses EC P-521 private key and strips d on to_public" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",) +
        %q("x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",) +
        %q("y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",) +
        %q("d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"})
      )
      jwk.private?.should be_true
      jwk["d"].as_s.should eq(
        "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
      )
      pub = jwk.to_public
      pub.public?.should be_true
      pub["d"]?.should be_nil
    end

    it "§3.3 parses RSA 2048-bit public key" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig",) +
        %q("n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_) +
        %q(AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP) +
        %q(e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg) +
        %q(_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",) +
        %q("e":"AQAB"})
      )
      jwk.kty.should eq("RSA")
      jwk.public?.should be_true
      jwk.private?.should be_false
      jwk["e"].as_s.should eq("AQAB")
    end

    it "§3.4 parses RSA 2048-bit private key and strips CRT fields on to_public" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig",) +
        %q("n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_) +
        %q(AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP) +
        %q(e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg) +
        %q(_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",) +
        %q("e":"AQAB",) +
        %q("d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK) +
        %q(1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHT) +
        %q(MEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP) +
        %q(5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",) +
        %q("p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0Az) +
        %q(Z0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",) +
        %q("q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8) +
        %q(lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",) +
        %q("dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8p) +
        %q(bt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",) +
        %q("dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6) +
        %q(og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",) +
        %q("qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8V) +
        %q(fBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"})
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

    it "§3.5 parses oct symmetric key (HS256, 256-bit)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      jwk.kty.should eq("oct")
      JOSE::Base64Url.decode(jwk["k"].as_s).size.should eq(32)
    end

    it "§3.6 parses oct symmetric key (A256GCM, 256-bit)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"1e571774-2e08-40da-8308-e8d68773842d","use":"enc",) +
        %q("alg":"A256GCM","k":"AAPapAv4LbFbiVawEjagUBluYqN5rhna-8nuldDvOx8"})
      )
      jwk.kty.should eq("oct")
      JOSE::Base64Url.decode(jwk["k"].as_s).size.should eq(32)
    end
  end

  # ── §4 JWS Examples ─────────────────────────────────────────────────────────
  # All §4 examples share the same payload:
  #   "It's a dangerous business, Frodo, going out your door. You step onto
  #    the road, and if you don't keep your feet, there's no knowing where
  #    you might be swept off to."
  # (a Tolkien quote — NOT a JSON object)

  describe "§4 JWS Examples" do
    it "§4.1 verifies RS256 compact token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig",) +
        %q("n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_) +
        %q(AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP) +
        %q(e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg) +
        %q(_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",) +
        %q("e":"AQAB",) +
        %q("d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK) +
        %q(1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHT) +
        %q(MEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP) +
        %q(5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",) +
        %q("p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0Az) +
        %q(Z0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",) +
        %q("q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8) +
        %q(lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",) +
        %q("dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8p) +
        %q(bt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",) +
        %q("dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6) +
        %q(og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",) +
        %q("qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8V) +
        %q(fBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"})
      )
      token =
        "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" \
        ".SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v" \
        "ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg" \
        "ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m" \
        "ZiB0by4" \
        ".MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U" \
        "4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0Rnlt" \
        "uYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0" \
        "ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd" \
        "6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg"
      valid, payload = JOSE::JWS.verify(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    it "§4.2 verifies PS384 compact token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig",) +
        %q("n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_) +
        %q(AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP) +
        %q(e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg) +
        %q(_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",) +
        %q("e":"AQAB",) +
        %q("d":"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK) +
        %q(1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHT) +
        %q(MEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP) +
        %q(5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",) +
        %q("p":"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0Az) +
        %q(Z0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",) +
        %q("q":"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8) +
        %q(lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",) +
        %q("dp":"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8p) +
        %q(bt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",) +
        %q("dq":"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6) +
        %q(og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",) +
        %q("qi":"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8V) +
        %q(fBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"})
      )
      token =
        "eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" \
        ".SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v" \
        "ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg" \
        "ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m" \
        "ZiB0by4" \
        ".cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6-tPid6Vrkl" \
        "HkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXzg-UD8biiReQFlfz28zGWV" \
        "sdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUj" \
        "vAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aCN_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTO" \
        "cbH510a6GYmJUAfmWjwZ6oD4ifKo8DYM-X72Eaw"
      valid, payload = JOSE::JWS.verify(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    it "§4.3 verifies ES512 compact token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",) +
        %q("x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",) +
        %q("y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",) +
        %q("d":"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"})
      )
      token =
        "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9" \
        ".SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v" \
        "ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg" \
        "ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m" \
        "ZiB0by4" \
        ".AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzo" \
        "NEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABl" \
        "sbEPX6sFY8OcGDqoRuBomu9xQ2"
      valid, payload = JOSE::JWS.verify(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    it "§4.4 verifies HS256 compact token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      token =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJj" \
        "NzAzNyJ9" \
        ".SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v" \
        "ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg" \
        "ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m" \
        "ZiB0by4" \
        ".s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
      valid, payload = JOSE::JWS.verify(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    # §4.5 — HS256 with detached payload: compact = "header..sig" (no payload segment)
    # Source: https://github.com/ietf-jose/cookbook/blob/master/jws/4_5.signature_with_detached_content.json
    it "§4.5 verifies HS256 compact token with detached content" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      # Compact token with empty payload segment (header..signature)
      token =
        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJj" \
        "NzAzNyJ9" \
        "..s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
      # The original payload (same Tolkien quote used in §4.4).
      # Note: "It's" and "there's" use U+2019 curly apostrophe;
      # "don't" uses ASCII apostrophe U+0027 — as in the RFC 7520 example.
      payload =
        "It\u2019s a dangerous business, Frodo, going out your door. " \
        "You step onto the road, and if you don't keep your feet, " \
        "there\u2019s no knowing where you might be swept off to."
      valid, returned = JOSE::JWS.verify(jwk, token, detached: payload)
      valid.should be_true
      returned.should contain("dangerous")
    end

    it "§4.6 verifies HS256 flattened JSON (alg protected, kid unprotected)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      token = %q({"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v) +
              %q(ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg) +
              %q(ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m) +
              %q(ZiB0by4",) +
              %q("protected":"eyJhbGciOiJIUzI1NiJ9",) +
              %q("header":{"kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},) +
              %q("signature":"bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"})
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    it "§4.7 verifies HS256 flattened JSON (alg+kid both unprotected, no protected header)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      token = %q({"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v) +
              %q(ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg) +
              %q(ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m) +
              %q(ZiB0by4",) +
              %q("header":{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},) +
              %q("signature":"xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"})
      valid, payload = JOSE::JWS.verify_json(jwk, token)
      valid.should be_true
      payload.should contain("dangerous")
    end

    it "§4.8 verifies RS256+ES512+HS256 general JSON (each key validates its signature)" do
      rsa_jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"bilbo.baggins@hobbiton.example","use":"sig",) +
        %q("n":"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_) +
        %q(AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpP) +
        %q(e7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg) +
        %q(_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw","e":"AQAB"})
      )
      ec_jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"sig","crv":"P-521",) +
        %q("x":"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",) +
        %q("y":"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"})
      )
      oct_jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037","use":"sig",) +
        %q("alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"})
      )
      payload_b64 =
        "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9v" \
        "ci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIg" \
        "ZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9m" \
        "ZiB0by4"
      token = {
        "payload"    => payload_b64,
        "signatures" => [
          {
            "protected" => "eyJhbGciOiJSUzI1NiJ9",
            "header"    => {"kid" => "bilbo.baggins@hobbiton.example"},
            "signature" => "MIsjqtVlOpa71KE-Mss8_Nq2YH4FGhiocsqrgi5NvyG53uoimic1tcMdSg-qptrzZc7CG6Svw2Y13TDIqHzTUrL_lR2ZFcryNFiHkSw129EghGpwkpxaTn_THJTCglNbADko1MZBCdwzJxwqZc-1RlpO2HibUYyXSwO97BSe0_evZKdjvvKSgsIqjytKSeAMbhMBdMma622_BG5t4sdbuCHtFjp9iJmkio47AIwqkZV1aIZsv33uPUqBBCXbYoQJwt7mxPftHmNlGoOSMxR_3thmXTCm4US-xiNOyhbm8afKK64jU6_TPtQHiJeQJxz9G3Tx-083B745_AfYOnlC9w",
          },
          {
            "header"    => {"alg" => "ES512", "kid" => "bilbo.baggins@hobbiton.example"},
            "signature" => "ARcVLnaJJaUWG8fG-8t5BREVAuTY8n8YHjwDO1muhcdCoFZFFjfISu0Cdkn9Ybdlmi54ho0x924DUz8sK7ZXkhc7AFM8ObLfTvNCrqcI3Jkl2U5IX3utNhODH6v7xgy1Qahsn0fyb4zSAkje8bAWz4vIfj5pCMYxxm4fgV3q7ZYhm5eD",
          },
          {
            "protected" => "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9",
            "signature" => "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0",
          },
        ],
      }.to_json
      valid_rsa, payload = JOSE::JWS.verify_json(rsa_jwk, token)
      valid_rsa.should be_true
      payload.should contain("dangerous")
      valid_ec, _ = JOSE::JWS.verify_json(ec_jwk, token)
      valid_ec.should be_true
      valid_oct, _ = JOSE::JWS.verify_json(oct_jwk, token)
      valid_oct.should be_true
    end
  end

  # ── §5 JWE Examples ─────────────────────────────────────────────────────────
  # All §5 active examples share the same plaintext:
  #   "You can trust us to stick with you through thick and thin–to the bitter
  #    end. And you can trust us to keep any secret of yours–closer than you
  #    keep it yourself. But you cannot trust us to let you face trouble alone,
  #    and go off without a word. We are your friends, Frodo."

  describe "§5 JWE Examples" do
    it "§5.1 decrypts RSA1_5 / A128CBC-HS256 token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"frodo.baggins@hobbiton.example","use":"enc",) +
        %q("n":"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhY) +
        %q(NvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI) +
        %q(1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy) +
        %q(pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ",) +
        %q("e":"AQAB",) +
        %q("d":"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wybQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiD) +
        %q(Tp4ntEPnqcKsyO5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6Oe1mY0vHTI3FucjSM86Nff4oI) +
        %q(ENt43r2fspgEPGRrdE6fpLc9Oaq-qeP1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PNmiuPUxO8O) +
        %q(pI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2vpzj85bQQ",) +
        %q("p":"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaEoekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21) +
        %q(aXf9-unynEpUsH7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ2VFmU",) +
        %q("q":"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_VF099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5Hr) +
        %q(J_XY2kfexJINb9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8d6Et0",) +
        %q("dp":"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTHQmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5) +
        %q(c125Fkdg317JVRDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsflo0rYU",) +
        %q("dq":"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9MbpFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUr) +
        %q(pa9fVYNot87ACfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14TkXlHE",) +
        %q("qi":"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZlXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaA) +
        %q(r5uR1hGQpSc7Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx2bQ_mM"})
      )
      token =
        "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUi" \
        "LCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" \
        ".laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePFvG2K-pvSlWc" \
        "9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2GXfz8YAImcc91Tfk0WXC2F5Xb" \
        "b71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcGTSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAf" \
        "gIe7Mv1rOTOI5I8NQqeXXW8VlzNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1w" \
        "x1BpyIfgvfjOhMBs9M8XL223Fg47xlGsMXdfuY-4jaqVw" \
        ".bbd5sTkYwhAIqfHsx8DayA" \
        ".0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_raa0HnLQ6s1P2sv" \
        "3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8OWzJv7eZVEqiWKdyVzFhPpiyQU28G" \
        "LOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZVyeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s" \
        "8uwIFcqt4r5GX8TKaI0zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP" \
        "78T2O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VWi7lzA6BP430m" \
        ".kvKuFBXHe5mQr4lqgobAUg"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    # §5.2 — RSA-OAEP / A256GCM with 4096-bit RSA key
    # Source: https://github.com/ietf-jose/cookbook/blob/master/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json
    it "§5.2 decrypts RSA-OAEP / A256GCM token (4096-bit RSA key)" do
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
      token =
        "eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUi" \
        "LCJlbmMiOiJBMjU2R0NNIn0" \
        ".rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXt" \
        "DePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-" \
        "_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8" \
        "Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6hu" \
        "IvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTS" \
        "z4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3" \
        "uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06Mv" \
        "ZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQ" \
        "hDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs" \
        ".-nBoKLH0YkLZPSI9" \
        ".o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRW" \
        "WeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNci" \
        "zPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1" \
        "QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525Dx" \
        "DfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw" \
        ".UCGiqJxhBI3IFVdPalHHvA"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    # §5.3 — PBES2-HS512+A256KW / A128CBC-HS256
    # Key: password "entrap_o–peter_long–credit_tun"
    # Source: https://github.com/ietf-jose/cookbook/blob/master/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json
    it "§5.3 decrypts PBES2-HS512+A256KW / A128CBC-HS256 token" do
      password = "entrap_o\u2013peter_long\u2013credit_tun"
      token =
        "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3hjaFl6NlpaY0hBIiwicDJj" \
        "Ijo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" \
        ".d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g" \
        ".VBiCzVHNoLiR3F4V82uoTQ" \
        ".23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IRsfywCRFzLxEcZBRnTvG3nh" \
        "zPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6lTF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3" \
        "dwejXBtIodN84PeqMb6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL_SEGll" \
        "v2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKdPQMTlVJKkqtV4Ru5LEVpBZXBnZrtVi" \
        "SOgyg6AiuwaS-rCrcD_ePOGSuxvgtrokAKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4Bq" \
        "Rpmdn_N-zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V3kobXZ77ulMwDs4p" \
        ".0HlwodAhOCILG5SQ2LQ9dg"
      plaintext = JOSE::JWE.block_decrypt(password, token)
      # §5.3 payload is a JWK Set containing 3 symmetric keys
      parsed = JSON.parse(plaintext)
      parsed["keys"].as_a.size.should eq(3)
      parsed["keys"].as_a.each(&.["kty"].as_s.should(eq("oct")))
    end

    it "§5.4 decrypts ECDH-ES+A128KW / A128GCM token (P-384 key)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384",) +
        %q("x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",) +
        %q("y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",) +
        %q("d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"})
      )
      # Canonical compact token from RFC 7520 §5.4 / ietf-jose cookbook.
      token =
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImtpZCI6InBlcmVncmluLnRvb2tAdHVja2" \
        "Jvcm91Z2guZXhhbXBsZSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0Iiwie" \
        "CI6InVCbzRrSFB3Nmtiang1bDB4b3dyZF9vWXpCbWF6LUdLRlp1NHhBRkZrYllpV2d1" \
        "dEVLNml1RURzUTZ3TmROZzMiLCJ5Ijoic3AzcDVTR2haVkMyZmFYdW1JLWU5SlUyTW8" \
        "4S3BvWXJGRHI1eVBOVnRXNFBnRXdaT3lRVEEtSmRhWTh0YjdFMCJ9LCJlbmMiOiJBM" \
        "TI4R0NNIn0" \
        ".0DJjBXri_kBcC46IkU5_Jk9BqaQeHdv2" \
        ".mH-G2zVqgztUtnW_" \
        ".tkZuOO9h95OgHJmkkrfLBisku8rGf6nzVxhRM3sVOhXgz5NJ76oID7lpnAi_cPWJRC" \
        "jSpAaUZ5dOR3Spy7QuEkmKx8-3RCMhSYMzsXaEwDdXta9Mn5B7cCBoJKB0IgEnj_qfo" \
        "1hIi-uEkUpOZ8aLTZGHfpl05jMwbKkTe2yK3mjF6SBAsgicQDVCkcY9BLluzx1RmC3O" \
        "RXaM0JaHPB93YcdSDGgpgBWMVrNU1ErkjcMqMoT_wtCex3w03XdLkjXIuEr2hWgeP-n" \
        "kUZTPU9EoGSPj6fAS-bSz87RCPrxZdj_iVyC6QWcqAu07WNhjzJEPc4jVntRJ6K53Ng" \
        "PQ5p99l3Z408OUqj4ioYezbS6vTPlQ" \
        ".WuGzxmcreYjpHGJoa17EBg"
      header = JOSE::JWE.peek_protected(token)
      header["alg"].as_s.should eq("ECDH-ES+A128KW")
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.5 decrypts ECDH-ES (direct) / A128CBC-HS256 token (P-256 key)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"meriadoc.brandybuck@buckland.example","use":"enc","crv":"P-256",) +
        %q("x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",) +
        %q("y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",) +
        %q("d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"})
      )
      # Protected header encodes: alg=ECDH-ES, kid=meriadoc.brandybuck@buckland.example,
      # epk={P-256 ephemeral key}, enc=A128CBC-HS256
      token =
        "eyJhbGciOiJFQ0RILUVTIiwia2lkIjoibWVyaWFkb2MuYnJhbmR5YnVja0BidWNrbGFuZC5leGFt" \
        "cGxlIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibVBVS1RfYkFXR0hJaGcw" \
        "VHBqanFWc1AxclhXUXVfdndWT0hIdE5rZFlvQSIsInkiOiI4QlFBc0ltR2VBUzQ2ZnlXdzVNaFlm" \
        "R1RUMElqQnBGdzJTUzM0RHY0SXJzIn0sImVuYyI6IkExMjhDQkMtSFMyNTYifQ" \
        "..yc9N8v5sYyv3iGQT926IUg" \
        ".BoDlwPnTypYq-ivjmQvAYJLb5Q6l-F3LIgQomlz87yW4OPKbWE1zSTEFjDfhU9IPIOSA9Bml4m7i" \
        "DFwA-1ZXvHteLDtw4R1XRGMEsDIqAYtskTTmzmzNa-_q4F_evAPUmwlO-ZG45Mnq4uhM1fm_D9rBt" \
        "WolqZSF3xGNNkpOMQKF1Cl8i8wjzRli7-IXgyirlKQsbhhqRzkv8IcY6aHl24j03C-AR2le1r7URU" \
        "hArM79BY8soZU0lzwI-sD5PZ3l4NDCCei9XkoIAfsXJWmySPoeRb2Ni5UZL4mYpvKDiwmyzGd65Kq" \
        "Vw7MsFfI_K767G9C9Azp73gKZD0DyUn1mn0WW5LmyX_yJ-3AROq8p1WZBfG-ZyJ6195_JGG2m9Csg" \
        ".WCCkNa-x4BeB9hIDIfFuhg"
      header = JOSE::JWE.peek_protected(token)
      header["alg"].as_s.should eq("ECDH-ES")
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.6 decrypts dir / A128GCM token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a","use":"enc",) +
        %q("alg":"A128GCM","k":"XctOhJAkA-pD9Lh7ZgW_2A"})
      )
      token =
        "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2Ei" \
        "LCJlbmMiOiJBMTI4R0NNIn0" \
        "..refa467QzzKx6QAB" \
        ".JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS" \
        "-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGR" \
        "PdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpG" \
        "bSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn" \
        "ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp" \
        ".vbb32Xvllea2OtmHAdccRQ"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    # §5.7 — A256GCMKW / A128CBC-HS256
    # Key: {"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc",
    #       "alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"}
    # Source: https://github.com/ietf-jose/cookbook/blob/master/jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json
    it "§5.7 decrypts A256GCMKW / A128CBC-HS256 token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc",) +
        %q("alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"})
      )
      token =
        "eyJhbGciOiJBMjU2R0NNS1ciLCJraWQiOiIxOGVjMDhlMS1iZmE5LTRkOTUtYjIwNS0yYjRkZDFk" \
        "NDMyMWQiLCJ0YWciOiJrZlBkdVZRM1QzSDZ2bmV3dC0ta3N3IiwiaXYiOiJLa1lUMEdYXzJqSGxm" \
        "cU5fIiwiZW5jIjoiQTEyOENCQy1IUzI1NiJ9" \
        ".lJf3HbOApxMEBkCMOoTnnABxs_CvTWUmZQ2ElLvYNok" \
        ".gz6NjyEFNm_vm8Gj6FwoFQ" \
        ".Jf5p9-ZhJlJy_IQ_byKFmI0Ro7w7G1QiaZpI8OaiVgD8EqoDZHyFKFBupS8iaEeVIgMqWmsuJKuo" \
        "VgzR3YfzoMd3GxEm3VxNhzWyWtZKX0gxKdy6HgLvqoGNbZCzLjqcpDiF8q2_62EVAbr2uSc2oaxF" \
        "mFuIQHLcqAHxy51449xkjZ7ewzZaGV3eFqhpco8o4DijXaG5_7kp3h2cajRfDgymuxUbWgLqaeNQa" \
        "JtvJmSMFuEOSAzw9Hdeb6yhdTynCRmu-kqtO5Dec4lT2OMZKpnxc_F1_4yDJFcqb5CiDSmA-psB2k" \
        "0JtjxAj4UPI61oONK7zzFIu4gBfjJCndsZfdvG7h8wGjV98QhrKEnR7xKZ3KCr0_qR1B-gxpNk3xWU" \
        ".DKW7jrb4WaRSNfbXVPlT5g"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.8 decrypts A128KW / A128GCM token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc",) +
        %q("alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"})
      )
      token =
        "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFh" \
        "YzgiLCJlbmMiOiJBMTI4R0NNIn0" \
        ".CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx" \
        ".Qx0pmsDa8KnJc9Jo" \
        ".AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD61A1hnWGetdg11c9" \
        "ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfeF0LwkcTtjbYKCsiNJQkcIp1yeM03Om" \
        "uiYSoYJVSpf7ej6zaYcMv3WwdxDFl8REwOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7" \
        "gDT6xW0JqHDPn_H-puQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZ" \
        "Raa8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF" \
        ".ER7MWJZ1FBI_NKvn7Zb1Lw"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.9 decrypts A128KW / A128GCM + DEFLATE compressed token" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc",) +
        %q("alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"})
      )
      token =
        "eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFh" \
        "YzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0" \
        ".5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi" \
        ".p9pUq6XHY0jfEZIl" \
        ".HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y" \
        "5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mx" \
        "gDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw" \
        ".VILuUwuIxaLVmh5X-T7kmA"
      plaintext = JOSE::JWE.block_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.10 A128KW / A128GCM with Additional Authenticated Data (JSON Serialization)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc",) +
        %q("alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"})
      )
      token = %q({) +
              %q("recipients":[{"encrypted_key":"4YiiQ_ZzH76TaIkJmYfRFgOV9MIpnx4X"}],) +
              %q("protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0",) +
              %q("iv":"veCx9ece2orS7c_N",) +
              %q("aad":"WyJ2Y2FyZCIsW1sidmVyc2lvbiIse30sInRleHQiLCI0LjAiXSxbImZuIix7fSwidGV4dCIsIk1lcmlhZG9jIEJyYW5keWJ1Y2siXSxbIm4iLHt9LCJ0ZXh0IixbIkJyYW5keWJ1Y2siLCJNZXJpYWRvYyIsIk1yLiIsIiJdXSxbImJkYXkiLHt9LCJ0ZXh0IiwiVEEgMjk4MiJdLFsiZ2VuZGVyIix7fSwidGV4dCIsIk0iXV1d",) +
              %q("ciphertext":"Z_3cbr0k3bVM6N3oSNmHz7Lyf3iPppGf3Pj17wNZqteJ0Ui8p74SchQP8xygM1oFRWCNzeIa6s6BcEtp8qEFiqTUEyiNkOWDNoF14T_4NFqF-p2Mx8zkbKxI7oPK8KNarFbyxIDvICNqBLba-v3uzXBdB89fzOI-Lv4PjOFAQGHrgv1rjXAmKbgkft9cB4WeyZw8MldbBhc-V_KWZslrsLNygon_JJWd_ek6LQn5NRehvApqf9ZrxB4aq3FXBxOxCys35PhCdaggy2kfUfl2OkwKnWUbgXVD1C6HxLIlqHhCwXDG59weHrRDQeHyMRoBljoV3X_bUTJDnKBFOod7nLz-cj48JMx3SnCZTpbQAkFV",) +
              %q("tag":"vOaH_Rajnpy_3hOtqvZHRA"})
      plaintext = JOSE::JWE.json_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.11 A128KW / A128GCM split protected/unprotected headers (JSON Serialization)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc",) +
        %q("alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"})
      )
      # protected contains only {"enc":"A128GCM"}; unprotected contains alg + kid
      token = %q({) +
              %q("recipients":[{"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"}],) +
              %q("unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},) +
              %q("protected":"eyJlbmMiOiJBMTI4R0NNIn0",) +
              %q("iv":"WgEJsDS9bkoXQ3nR",) +
              %q("ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf",) +
              %q("tag":"fNYLqpUe84KD45lvDiaBAQ"})
      plaintext = JOSE::JWE.json_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.12 A128KW / A128GCM content-only (no protected header, JSON Serialization)" do
      jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc",) +
        %q("alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"})
      )
      # No protected header — alg, enc, kid all in unprotected
      token = %q({) +
              %q("recipients":[{"encrypted_key":"244YHfO_W7RMpQW81UjQrZcq5LSyqiPv"}],) +
              %q("unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM"},) +
              %q("iv":"YihBoVOGsR1l7jCD",) +
              %q("ciphertext":"qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF",) +
              %q("tag":"e2m0Vm7JvjK2VpCKXS-kyg"})
      plaintext = JOSE::JWE.json_decrypt(jwk, token)
      plaintext.should contain("trust us")
    end

    it "§5.13 multi-recipient (RSA1_5 + ECDH-ES+A256KW + A256GCMKW), decrypts with each key" do
      token = %q({) +
              %q("recipients":[) +
              %q({"encrypted_key":"dYOD28kab0Vvf4ODgxVAJXgHcSZICSOp8M51zjwj4w6Y5G4XJQsNNIBiqyvUUAOcpL7S7-cFe7Pio7gV_Q06WmCSa-vhW6me4bWrBf7cHwEQJdXihidAYWVajJIaKMXMvFRMV6iDlRr076DFthg2_AV0_tSiV6xSEIFqt1xnYPpmP91tc5WJDOGb-wqjw0-b-S1laS11QVbuP78dQ7Fa0zAVzzjHX-xvyM2wxj_otxr9clN1LnZMbeYSrRicJK5xodvWgkpIdkMHo4LvdhRRvzoKzlic89jFWPlnBq_V4n5trGuExtp_-dbHcGlihqc_wGgho9fLMK8JOArYLcMDNQ",) +
              %q("header":{"alg":"RSA1_5","kid":"frodo.baggins@hobbiton.example"}},) +
              %q({"encrypted_key":"ExInT0io9BqBMYF6-maw5tZlgoZXThD1zWKsHixJuw_elY4gSSId_w",) +
              %q("header":{"alg":"ECDH-ES+A256KW","kid":"peregrin.took@tuckborough.example",) +
              %q("epk":{"kty":"EC","crv":"P-384",) +
              %q("x":"Uzdvk3pi5wKCRc1izp5_r0OjeqT-I68i8g2b8mva8diRhsE2xAn2DtMRb25Ma2CX",) +
              %q("y":"VDrRyFJh-Kwd1EjAgmj5Eo-CTHAZ53MC7PjjpLioy3ylEjI1pOMbw91fzZ84pbfm"}}},) +
              %q({"encrypted_key":"a7CclAejo_7JSuPB8zeagxXRam8dwCfmkt9-WyTpS1E",) +
              %q("header":{"alg":"A256GCMKW","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",) +
              %q("tag":"59Nqh1LlYtVIhfD3pgRGvw","iv":"AvpeoPZ9Ncn9mkBn"}}) +
              %q(],) +
              %q("unprotected":{"cty":"text/plain"},) +
              %q("protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",) +
              %q("iv":"VgEIHY20EnzUtZFl2RpB1g",) +
              %q("ciphertext":"ajm2Q-OpPXCr7-MHXicknb1lsxLdXxK_yLds0KuhJzfWK04SjdxQeSw2L9mu3a_k1C55kCQ_3xlkcVKC5yr__Is48VOoK0k63_QRM9tBURMFqLByJ8vOYQX0oJW4VUHJLmGhF-tVQWB7Kz8mr8zeE7txF0MSaP6ga7-siYxStR7_G07Thd1jh-zGT0wxM5g-VRORtq0K6AXpLlwEqRp7pkt2zRM0ZAXqSpe1O6FJ7FHLDyEFnD-zDIZukLpCbzhzMDLLw2-8I14FQrgi-iEuzHgIJFIJn2wh9Tj0cg_kOZy9BqMRZbmYXMY9YQjorZ_P_JYG3ARAIF3OjDNqpdYe-K_5Q5crGJSDNyij_ygEiItR5jssQVH2ofDQdLChtazE",) +
              %q("tag":"BESYyFN7T09KY7i8zKs5_g"})

      # Recipient 1 — RSA1_5
      rsa_jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"frodo.baggins@hobbiton.example","use":"enc",) +
        %q("n":"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegTHVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5UNwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4cR5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oypBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYAVotGlvMQ",) +
        %q("e":"AQAB",) +
        %q("d":"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wybQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PNmiuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2vpzj85bQQ",) +
        %q("p":"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaEoekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ2VFmU",) +
        %q("q":"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_VF099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8d6Et0",) +
        %q("dp":"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTHQmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JVRDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsflo0rYU",) +
        %q("dq":"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9MbpFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87ACfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14TkXlHE",) +
        %q("qi":"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZlXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx2bQ_mM"})
      )
      JOSE::JWE.json_decrypt(rsa_jwk, token).should contain("trust us")

      # Recipient 2 — ECDH-ES+A256KW (P-384)
      ec_jwk = JOSE::JWK.from_binary(
        %q({"kty":"EC","kid":"peregrin.took@tuckborough.example","use":"enc","crv":"P-384",) +
        %q("x":"YU4rRUzdmVqmRtWOs2OpDE_T5fsNIodcG8G5FWPrTPMyxpzsSOGaQLpe2FpxBmu2",) +
        %q("y":"A8-yxCHxkfBz3hKZfI1jUYMjUhsEveZ9THuwFjH2sCNdtksRJU7D5-SkgaFL1ETP",) +
        %q("d":"iTx2pk7wW-GqJkHcEkFQb2EFyYcO7RugmaW3mRrQVAOUiPommT0IdnYK2xDlZh-j"})
      )
      JOSE::JWE.json_decrypt(ec_jwk, token).should contain("trust us")

      # Recipient 3 — A256GCMKW
      oct_jwk = JOSE::JWK.from_binary(
        %q({"kty":"oct","kid":"18ec08e1-bfa9-4d95-b205-2b4dd1d4321d","use":"enc",) +
        %q("alg":"A256GCMKW","k":"qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8"})
      )
      JOSE::JWE.json_decrypt(oct_jwk, token).should contain("trust us")
    end
  end

  # ── §6 Nesting Signatures and Encryption ─────────────────────────────────────

  describe "§6 Nesting Signatures and Encryption" do
    it "§6 PS256 JWS nested inside RSA-OAEP / A128GCM JWE (JSON Serialization)" do
      # Inner signing key — hobbiton.example, PS256
      sig_jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"hobbiton.example","use":"sig",) +
        %q("n":"kNrPIBDXMU6fcyv5i-QHQAQ-K8gsC3HJb7FYhYaw8hXbNJa-t8q0lDKwLZgQXYV-ffWxXJv5GGrlZE4GU52lfMEegTDzYTrRQ3tepgKFjMGg6Iy6fkl1ZNsx2gEonsnlShfzA9GJwRTmtKPbk1s-hwx1IU5AT-AIelNqBgcF2vE5W25_SGGBoaROVdUYxqETDggM1z5cKV4ZjDZ8-lh4oVB07bkac6LQdHpJUUySH_Er20DXx30Kyi97PciXKTS-QKXnmm8ivyRCmux22ZoPUind2BKC5OiG4MwALhaL2Z2k8CsRdfy-7dg7z41Rp6D0ZeEvtaUp4bX4aKraL4rTfw",) +
        %q("e":"AQAB",) +
        %q("d":"ZLe_TIxpE9-W_n2VBa-HWvuYPtjvxwVXClJFOpJsdea8g9RMx34qEOEtnoYc2un3CZ3LtJi-mju5RAT8YSc76YJds3ZVw0UiO8mMBeG6-iOnvgobobNx7K57-xjTJZU72EjOr9kB7z6ZKwDDq7HFyCDhUEcYcHFVc7iL_6TibVhAhOFONWlqlJgEgwVYd0rybNGKifdnpEbwyHoMwY6HM1qvnEFgP7iZ0YzHUT535x6jj4VKcdA7ZduFkhUauysySEW7mxZM6fj1vdjJIy9LD1fIz30Xv4ckoqhKF5GONU6tNmMmNgAD6gIViyEle1PrIxl1tBhCI14bRW-zrpHgAQ",) +
        %q("p":"yKWYoNIAqwMRQlgIBOdT1NIcbDNUUs2Rh-pBaxD_mIkweMt4Mg-0-B2iSYvMrs8horhonV7vxCQagcBAATGW-hAafUehWjxWSH-3KccRM8toL4e0q7M-idRDOBXSoe7Z2-CV2x_ZCY3RP8qp642R13WgXqGDIM4MbUkZSjcY9-c",) +
        %q("q":"uND4o15V30KDzf8vFJw589p1vlQVQ3NEilrinRUPHkkxaAzDzccGgrWMWpGxGFFnNL3w5CqPLeU76-5IVYQq0HwYVl0hVXQHr7sgaGu-483Ad3ENcL23FrOnF45m7_2ooAstJDe49MeLTTQKrSIBl_SKvqpYvfSPTczPcZkh9Kk",) +
        %q("dp":"jmTnEoq2qqa8ouaymjhJSCnsveUXnMQC2gAneQJRQkFqQu-zV2PKPKNbPvKVyiF5b2-L3tM3OW2d2iNDyRUWXlT7V5l0KwPTABSTOnTqAmYChGi8kXXdlhcrtSvXldBakC6saxwI_TzGGY2MVXzc2ZnCvCXHV4qjSxOrfP3pHFU",) +
        %q("dq":"R9FUvU88OVzEkTkXl3-5-WusE4DjHmndeZIlu3rifBdfLpq_P-iWPBbGaq9wzQ1c-J7SzCdJqkEJDv5yd2C7rnZ6kpzwBh_nmL8zscAk1qsunnt9CJGAYz7-sGWy1JGShFazfP52ThB4rlCJ0YuEaQMrIzpY77_oLAhpmDA0hLk",) +
        %q("qi":"S8tC7ZknW6hPITkjcwttQOPLVmRfwirRlFAViuDb8NW9CrV_7F2OqUZCqmzHTYAumwGFHI1WVRep7anleWaJjxC_1b3fq_al4qH3Pe-EKiHg6IMazuRtZLUROcThrExDbF5dYbsciDnfRUWLErZ4N1Be0bnxYuPqxwKd9QZwMo0"})
      )
      # Outer encryption key — samwise.gamgee, RSA-OAEP / A128GCM
      enc_jwk = JOSE::JWK.from_binary(
        %q({"kty":"RSA","kid":"samwise.gamgee@hobbiton.example","use":"enc","alg":"RSA-OAEP",) +
        %q("n":"wbdxI55VaanZXPY29Lg5hdmv2XhvqAhoxUkanfzf2-5zVUxa6prHRrI4pP1AhoqJRlZfYtWWd5mmHRG2pAHIlh0ySJ9wi0BioZBl1XP2e-C-FyXJGcTy0HdKQWlrfhTm42EW7Vv04r4gfao6uxjLGwfpGrZLarohiWCPnkNrg71S2CuNZSQBIPGjXfkmIy2tl_VWgGnL22GplyXj5YlBLdxXp3XeStsqo571utNfoUTU8E4qdzJ3U1DItoVkPGsMwlmmnJiwA7sXRItBCivR4M5qnZtdw-7v4WuR4779ubDuJ5nalMv2S66-RPcnFAzWSKxtBDnFJJDGIUe7Tzizjg1nms0Xq_yPub_UOlWn0ec85FCft1hACpWG8schrOBeNqHBODFskYpUc2LC5JA2TaPF2dA67dg1TTsC_FupfQ2kNGcE1LgprxKHcVWYQb86B-HozjHZcqtauBzFNV5tbTuB-TpkcvJfNcFLlH3b8mb-H_ox35FjqBSAjLKyoeqfKTpVjvXhd09knwgJf6VKq6UC418_TOljMVfFTWXUxlnfhOOnzW6HSSzD1c9WrCuVzsUMv54szidQ9wf1cYWf3g5qFDxDQKis99gcDaiCAwM3yEBIzuNeeCa5dartHDb1xEB_HcHSeYbghbMjGfasvKn0aZRsnTyC0xhWBlsolZE",) +
        %q("e":"AQAB",) +
        %q("d":"n7fzJc3_WG59VEOBTkayzuSMM780OJQuZjN_KbH8lOZG25ZoA7T4Bxcc0xQn5oZE5uSCIwg91oCt0JvxPcpmqzaJZg1nirjcWZ-oBtVk7gCAWq-B3qhfF3izlbkosrzjHajIcY33HBhsy4_WerrXg4MDNE4HYojy68TcxT2LYQRxUOCf5TtJXvM8olexlSGtVnQnDRutxEUCwiewfmmrfveEogLx9EA-KMgAjTiISXxqIXQhWUQX1G7v_mV_Hr2YuImYcNcHkRvp9E7ook0876DhkO8v4UOZLwA1OlUX98mkoqwc58A_Y2lBYbVx1_s5lpPsEqbbH-nqIjh1fL0gdNfihLxnclWtW7pCztLnImZAyeCWAG7ZIfv-Rn9fLIv9jZ6r7r-MSH9sqbuziHN2grGjD_jfRluMHa0l84fFKl6bcqN1JWxPVhzNZo01yDF-1LiQnqUYSepPf6X3a2SOdkqBRiquE6EvLuSYIDpJq3jDIsgoL8Mo1LoomgiJxUwL_GWEOGu28gplyzm-9Q0U0nyhEf1uhSR8aJAQWAiFImWH5W_IQT9I7-yrindr_2fWQ_i1UgMsGzA7aOGzZfPljRy6z-tY_KuBG00-28S_aWvjyUc-Alp8AUyKjBZ-7CWH32fGWK48j1t-zomrwjL_mnhsPbGs0c9WsWgRzI-K8gE",) +
        %q("p":"7_2v3OQZzlPFcHyYfLABQ3XP85Es4hCdwCkbDeltaUXgVy9l9etKghvM4hRkOvbb01kYVuLFmxIkCDtpi-zLCYAdXKrAK3PtSbtzld_XZ9nlsYa_QZWpXB_IrtFjVfdKUdMz94pHUhFGFj7nr6NNxfpiHSHWFE1zD_AC3mY46J961Y2LRnreVwAGNw53p07Db8yD_92pDa97vqcZOdgtybH9q6uma-RFNhO1AoiJhYZj69hjmMRXx-x56HO9cnXNbmzNSCFCKnQmn4GQLmRj9sfbZRqL94bbtE4_e0Zrpo8RNo8vxRLqQNwIy85fc6BRgBJomt8QdQvIgPgWCv5HoQ",) +
        %q("q":"zqOHk1P6WN_rHuM7ZF1cXH0x6RuOHq67WuHiSknqQeefGBA9PWs6ZyKQCO-O6mKXtcgE8_Q_hA2kMRcKOcvHil1hqMCNSXlflM7WPRPZu2qCDcqssd_uMbP-DqYthH_EzwL9KnYoH7JQFxxmcv5An8oXUtTwk4knKjkIYGRuUwfQTus0w1NfjFAyxOOiAQ37ussIcE6C6ZSsM3n41UlbJ7TCqewzVJaPJN5cxjySPZPD3Vp01a9YgAD6a3IIaKJdIxJS1ImnfPevSJQBE79-EXe2kSwVgOzvt-gsmM29QQ8veHy4uAqca5dZzMs7hkkHtw1z0jHV90epQJJlXXnH8Q",) +
        %q("dp":"19oDkBh1AXelMIxQFm2zZTqUhAzCIr4xNIGEPNoDt1jK83_FJA-xnx5kA7-1erdHdms_Ef67HsONNv5A60JaR7w8LHnDiBGnjdaUmmuO8XAxQJ_ia5mxjxNjS6E2yD44USo2JmHvzeeNczq25elqbTPLhUpGo1IZuG72FZQ5gTjXoTXC2-xtCDEUZfaUNh4IeAipfLugbpe0JAFlFfrTDAMUFpC3iXjxqzbEanflwPvj6V9iDSgjj8SozSM0dLtxvu0LIeIQAeEgT_yXcrKGmpKdSO08kLBx8VUjkbv_3Pn20Gyu2YEuwpFlM_H1NikuxJNKFGmnAq9LcnwwT0jvoQ",) +
        %q("dq":"S6p59KrlmzGzaQYQM3o0XfHCGvfqHLYjCO557HYQf72O9kLMCfd_1VBEqeD-1jjwELKDjck8kOBl5UvohK1oDfSP1DleAy-cnmL29DqWmhgwM1ip0CCNmkmsmDSlqkUXDi6sAaZuntyukyflI-qSQ3C_BafPyFaKrt1fgdyEwYa08pESKwwWisy7KnmoUvaJ3SaHmohFS78TJ25cfc10wZ9hQNOrIChZlkiOdFCtxDqdmCqNacnhgE3bZQjGp3n83ODSz9zwJcSUvODlXBPc2AycH6Ci5yjbxt4Ppox_5pjm6xnQkiPgj01GpsUssMmBN7iHVsrE7N2iznBNCeOUIQ",) +
        %q("qi":"FZhClBMywVVjnuUud-05qd5CYU0dK79akAgy9oX6RX6I3IIIPckCciRrokxglZn-omAY5CnCe4KdrnjFOT5YUZE7G_Pg44XgCXaarLQf4hl80oPEf6-jJ5Iy6wPRx7G2e8qLxnh9cOdf-kRqgOS3F48Ucvw3ma5V6KGMwQqWFeV31XtZ8l5cVI-I3NzBS7qltpUVgz2Ju021eyc7IlqgzR98qKONl27DuEES0aK0WE97jnsyO27Yp88Wa2RiBrEocM89QZI1seJiGDizHRUP4UZxw9zsXww46wy0P6f9grnYp7t8LkyDDk8eoI4KX6SNMNVcyVS9IWjlq8EzqZEKIA"})
      )
      # JWE output in general JSON form (from RFC 7520 cookbook §6)
      jwe_json =
        %q({"recipients":[{"encrypted_key":"a0JHRoITfpX4qRewImjlStn8m3CPxBV1ueYlVhjurCyrBg3I7YhCRYjphDOOS4E7rXbr2) +
          %q(Fn6NyQq-A-gqT0FXqNjVOGrG-bi13mwy7RoYhjTkBEC6P7sMYMXXx4gzMedpiJHQVeyI-zkZV7A9matpgevAJWrXzOUysYGTtwoSN6) +
          %q(gtUVtlLaivjvb21O0ul4YxSHV-ByK1kyeetRp_fuYJxHoKLQL9P424sKx2WGYb4zsBIPF4ssl_e5IR7nany-25_UmC2urosNkoFz9cQ82) +
          %q(MypZP8gqbQJyPN-Fpp4Z-5o6yV64x6yzDUF_5JCIdl-Qv6H5dMVIY7q1eKpXcV1lWO_2FefEBqXxXvIjLeZivjNkzogCq3-IapSjVFnMj) +
          %q(BxjpYLT8muaawo1yy1XXMuinIpNcOY3n4KKrXLrCcteX85m4IIHMZa38s1Hpr56fPPseMA-Jltmt-a9iEDtOzhtxz8AXy9tsCAZV2XBWNG8) +
          %q(c3kJusAamBKOYwfk7JhLRDgOnJjlJLhn7TI4UxDp9dCmUXEN6z0v23W15qJIEXNJtqnblpymooeWAHCT4e_Owbim1g0AEpTHUdA2iiLNs9) +
          %q(WTX_H_TXuPC8yDDhi1smxS_X_xpkIHkiIHWDOLx03BpqDTivpKkBYwqP2UZkcxqX2Fo_GnVrNwlK7Lgxw6FSQvDO0"}],) +
          %q("protected":"eyJhbGciOiJSU0EtT0FFUCIsImN0eSI6IkpXVCIsImVuYyI6IkExMjhHQ00ifQ",) +
          %q("iv":"GbX1i9kXz0sxXPmA",) +
          %q("ciphertext":"SZI4IvKHmwpazl_pJQXX3mHv1ANnOU4Wf9-utWYUcKrBNgCe2OFMf66cSJ8k2QkxaQD3_R60MGE9ofomwtky3GFx) +
          %q(MeGRjtpMt9OAvVLsAXB0_UTCBGyBg3C2bWLXqZlfJAAoJRUPRk-BimYZY81zVBuIhc7HsQePCpu33SzMsFHjn4lP_idrJz_glZTNgKDt8zdnU) +
          %q(PauKTKDNOH1DD4fuzvDYfDIAfqGPyL5sVRwbiXpXdGokEszM-9ChMPqW1QNhzuX_Zul3bvrJwr7nuGZs4cUScY3n8yE3AHCLurgls-A9mz1X38x) +
          %q(EaulV18l4Fg9tLejdkAuQZjPbqeHQBJe4IwGD5Ee0dQ-Mtz4NnhkIWx-YKBb_Xo2zI3Q_1sYjKUuis7yWW-HTr_vqvFt0bj7WJf2vzB0TZ3dvsoG) +
          %q(aTvPH2dyWwumUrlx4gmPUzBdwTO6ubfYSDUEEz5py0d_OtWeUSYcCYBKD-aM7tXg26qJo21gYjLfhn9zy-W19sOCZGuzgFjPhawXHpvnj_t-0_ES96) +
          %q(kogjJLxS1IMU9Y5XmnwZMyNc9EIwnogsCg-hVuvzyP0sIruktmI94_SL1xgMl7o03phcTMxtlMizR88NKU1WkBsiXMCjy1Noue7MD-ShDp5dmM",) +
          %q("tag":"KnIKEhN8U-3C9s4gtSpjSw"})

      compact_jws = JOSE::JWE.json_decrypt(enc_jwk, jwe_json)
      valid, claims_json = JOSE::JWS.verify(sig_jwk.to_public, compact_jws)
      valid.should be_true
      claims = JSON.parse(claims_json)
      claims["iss"].as_s.should eq("hobbiton.example")
      claims["http://example.com/is_root"].as_bool.should be_true
    end
  end
end
