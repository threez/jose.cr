require "compress/deflate"
require "openssl"
require "openssl/hmac"
require "openssl/digest"
require "json"
require "ed25519"
require "./jose/lib_crypto"
require "./jose/base64url"
require "./jose/encrypted_binary"
require "./jose/signed_binary"
require "./jose/jwa/aes_kw"
require "./jose/jwa/pbes2"
require "./jose/jwa/concat_kdf"
require "./jose/jwa/aes_gcm"
require "./jose/jwa/aes_cbc_hmac"
require "./jose/jwa/ecdh_es"
require "./jose/jwa/rsa_kw"
require "./jose/jwk"
require "./jose/jwks"
require "./jose/jwe"
require "./jose/jws"
require "./jose/jwt"

# JOSE (JSON Object Signing and Encryption) implementation for Crystal.
#
# Provides compact and JSON serialization for JWS (RFC 7515), JWE (RFC 7516),
# and JWT (RFC 7519) backed by OpenSSL via low-level bindings. All RFC 7520
# test vectors pass.
# Keys are represented as JWK (RFC 7517), key sets as JWKS (RFC 7517 §5),
# and algorithms follow JWA (RFC 7518).
#
# **Supported key types** (`JWK#kty`)
# - `"EC"` — P-256, P-384, P-521
# - `"RSA"` — any bit length (2048+ recommended)
# - `"oct"` — symmetric (HMAC / AES)
# - `"OKP"` — Ed25519
#
# **JWS algorithms** (`JWS`)
# - HMAC: `HS256`, `HS384`, `HS512`
# - ECDSA: `ES256`, `ES384`, `ES512`
# - RSA PKCS#1 v1.5: `RS256`, `RS384`, `RS512`
# - RSA PSS: `PS256`, `PS384`, `PS512`
# - Edwards-curve: `EdDSA`
#
# **JWE key-wrap algorithms** (`JWE`)
# - Direct: `dir`
# - AES Key Wrap: `A128KW`, `A192KW`, `A256KW`
# - ECDH-ES: `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`
# - RSA: `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5`
# - AES-GCM Key Wrap: `A128GCMKW`, `A192GCMKW`, `A256GCMKW`
# - PBES2: `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`
#
# **JWE content-encryption algorithms**
# - AES-GCM: `A128GCM`, `A192GCM`, `A256GCM`
# - AES-CBC-HMAC: `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`
#
# ## Scenario 1 — Symmetric encryption (`dir` + `A128GCM`)
#
# Alice and Bob share a 16-byte secret key out-of-band.
#
# ```
# require "jose"
#
# # Both Alice and Bob hold the same key.
# key = JOSE::JWK.generate_key_oct(size: 16)
#
# # Alice encrypts a message.
# token = key.block_encrypt("Hello, Bob!")
# # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0...<iv>.<ciphertext>.<tag>"
#
# # Bob decrypts with the same key.
# plaintext = key.block_decrypt(token)
# # => "Hello, Bob!"
# ```
#
# ## Scenario 2 — Asymmetric encryption (ECDH-ES, EC key pair)
#
# Alice generates a P-256 key pair and publishes the public half. Bob encrypts
# a message to Alice's public key; only Alice (with the private key) can decrypt.
#
# ```
# require "jose"
#
# # Alice generates her key pair and shares the public key.
# alice_private = JOSE::JWK.generate_key_ec
# alice_public = alice_private.to_public
#
# # Bob encrypts to Alice's public key (default alg: ECDH-ES+A256KW, enc: A256GCM).
# token = alice_public.block_encrypt("Secret for Alice")
#
# # Alice decrypts with her private key.
# plaintext = alice_private.block_decrypt(token)
# # => "Secret for Alice"
# ```
#
# ## Scenario 3 — JWS sign and verify (Ed25519 / OKP)
#
# Alice signs a JSON payload with an Ed25519 key. Bob verifies the signature
# using only Alice's public key.
#
# ```
# require "jose"
#
# # Alice generates an Ed25519 signing key pair.
# alice_private = JOSE::JWK.generate_key_okp
# alice_public = alice_private.to_public
#
# # Alice signs a payload (default alg: EdDSA).
# signed = alice_private.sign("{\"sub\":\"alice\",\"iss\":\"example.com\"}")
#
# # Bob verifies using Alice's public key.
# valid, payload = alice_public.verify(signed)
# valid   # => true
# payload # => "{\"sub\":\"alice\",\"iss\":\"example.com\"}"
# ```
#
# ## Scenario 4 — JWT: sign claims and verify (HS256)
#
# Alice signs a claims hash as a JWT and Bob verifies it using the same
# shared secret, enforcing that only `HS256` is accepted.
#
# ```
# require "jose"
#
# jwk = JOSE::JWK.generate_key_oct
#
# jwt = JOSE::JWT.from_map({
#   "sub" => JSON::Any.new("alice"),
#   "iss" => JSON::Any.new("example.com"),
# })
#
# signed = JOSE::JWT.sign(jwk, jwt)
# valid, decoded, _header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed)
# valid               # => true
# decoded["sub"].as_s # => "alice"
# ```
#
# ## Scenario 5 — JWKS: publish public keys and look up by kid
#
# Build a two-key set, strip private material for publication, and look up a
# key by `kid` during token verification.
#
# ```
# require "jose"
#
# k1 = JOSE::JWK.generate_key_ec
# k1_with_kid = k1.with(kid: "sig")
# k2 = JOSE::JWK.generate_key_oct
# k2_with_kid = k2.with(kid: "enc")
#
# jwks = JOSE::JWKS.new([k1_with_kid, k2_with_kid])
#
# # Publish only public key material (e.g. as /.well-known/jwks.json).
# public_jwks = jwks.to_public
# public_jwks.to_binary # => {"keys":[...]}
#
# # Look up a key by kid during token verification.
# key = jwks["sig"]
# ```
#
# ## Scenario 6 — Combined: encrypt then sign
#
# Alice encrypts a message for Bob, then signs the compact ciphertext with her
# own EC key. Bob verifies the signature first, then decrypts.
#
# ```
# require "jose"
#
# # Generate keys.
# alice_signing_private = JOSE::JWK.generate_key_ec
# alice_signing_public = alice_signing_private.to_public
# bob_private = JOSE::JWK.generate_key_ec
# bob_public = bob_private.to_public
#
# # Alice encrypts for Bob, then signs the compact token.
# encrypted_token = bob_public.block_encrypt("Eyes only, Bob.")
# signed_envelope = alice_signing_private.sign(encrypted_token.compact)
#
# # Bob first verifies Alice's signature …
# valid, compact_jwe = alice_signing_public.verify(signed_envelope)
# raise "Signature invalid!" unless valid
#
# # … then decrypts.
# plaintext = bob_private.block_decrypt(compact_jwe)
# # => "Eyes only, Bob."
# ```
#
# ## Scenario 7 — Password-based encryption (PBES2)
#
# A password string is used directly as the key material. No JWK is required.
# The default algorithm is PBES2-HS512+A256KW with A256GCM content-encryption
# and 310 000 PBKDF2 iterations (NIST-recommended minimum).
#
# ```
# require "jose"
#
# password = "correct horse battery staple"
#
# # Encrypt.
# token = JOSE::JWE.block_encrypt(password, "sensitive data")
#
# # Decrypt.
# plaintext = JOSE::JWE.block_decrypt(password, token)
# # => "sensitive data"
# ```
#
# ## Scenario 8 — JWS JSON Serialization (RFC 7515 §7.2)
#
# `JWS.sign_json` returns a JSON object instead of a compact token.
# The flattened form carries a single signature; the general form (built
# manually or by a third party) may carry multiple. `JWS.verify_json`
# handles both forms and iterates signatures until one verifies.
#
# ```
# require "jose"
#
# jwk = JOSE::JWK.generate_key_ec
#
# # Sign — produces {"payload":…,"protected":…,"signature":…}
# json_token = JOSE::JWS.sign_json(jwk, %({"sub":"alice"}))
#
# valid, payload = JOSE::JWS.verify_json(jwk, json_token)
# valid   # => true
# payload # => "{\"sub\":\"alice\"}"
# ```
#
# ## Scenario 9 — JWE JSON Serialization (RFC 7516 §7.2)
#
# `JWE.json_encrypt` returns a JSON object (flattened form, single recipient).
# `JWE.json_decrypt` accepts both flattened and general forms and iterates
# recipients until one can be unwrapped with the supplied key.
# An optional `aad:` parameter adds Additional Authenticated Data.
#
# ```
# require "jose"
#
# jwk = JOSE::JWK.generate_key_oct
#
# # Encrypt — produces {"protected":…,"encrypted_key":…,"iv":…,"ciphertext":…,"tag":…}
# json_token = JOSE::JWE.json_encrypt(jwk, "hello json")
#
# plaintext = JOSE::JWE.json_decrypt(jwk, json_token)
# # => "hello json"
# ```
module JOSE
  # Current library version.
  VERSION = "1.3.1"
end
