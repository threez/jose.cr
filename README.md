# jose

[![CI](https://github.com/threez/jose.cr/actions/workflows/ci.yml/badge.svg)](https://github.com/threez/jose.cr/actions/workflows/ci.yml)
[![https://threez.github.io/jose.cr/](https://badgen.net/badge/api/documentation/green)](https://threez.github.io/jose.cr/)

JSON Object Signing and Encryption (JOSE) for Crystal — JWS (signing), JWE
(encryption), JWT, and JWKS (key sets), in both compact and JSON serialization,
backed by OpenSSL.

Implements the following RFCs:

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) — JSON Web Signature (JWS)
- [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516) — JSON Web Encryption (JWE)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) — JSON Web Key (JWK / JWKS)
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) — JSON Web Algorithms (JWA)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT)
- [RFC 7520](https://www.rfc-editor.org/rfc/rfc7520) — JOSE Cookbook (test vectors, fully covered)
- [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) — JWS Unencoded Payload Option
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) — JSON Web Token Best Current Practices

Heavily inspired by [ruby-jose](https://github.com/potatosalad/ruby-jose) and
[erlang-jose](https://hexdocs.pm/jose/).

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     jose:
       github: threez/jose
   ```

2. Run `shards install`

## Usage

### Sign & verify (HS256)

```crystal
require "jose"

# Use a shared secret key with HMAC-SHA256.
jwk = JOSE::JWK.from_oct("symmetric key".to_slice)

# JWK as JSON.
jwk.to_binary
# => "{\"k\":\"c3ltbWV0cmljIGtleQ\",\"kty\":\"oct\"}"

# Sign a message.
signed = jwk.sign("test")
signed.compact
# => "eyJhbGciOiJIUzI1NiJ9.dGVzdA.VlZz7pJCnos0k-WUL9O9RoT9N--2kHSakNIdOg-MIro"

# Verify with the same key.
valid, message = jwk.verify(signed)
# => true, "test"
```

### Encrypt & decrypt (ECDH-ES, EC P-256)

```crystal
require "jose"

# Alice generates a key pair and publishes the public half.
alice_private = JOSE::JWK.generate_key_ec
alice_public  = alice_private.to_public

# Bob encrypts to Alice's public key.
token = alice_public.block_encrypt("Secret for Alice")

# Alice decrypts with her private key.
plaintext = alice_private.block_decrypt(token)
# => "Secret for Alice"
```

### JWT (RFC 7519)

```crystal
require "jose"

# Generate a shared HMAC key.
jwk = JOSE::JWK.generate_key_oct

# Build a claims map and wrap it in a JWT.
jwt = JOSE::JWT.from_map({
  "sub" => JSON::Any.new("alice"),
  "iss" => JSON::Any.new("example.com"),
})

# Sign — the "typ": "JWT" header is added automatically.
signed = JOSE::JWT.sign(jwk, jwt)

# Verify: enforce algorithm allowlist, issuer, audience, and expiry (RFC 8725).
jwt.exp = Time.utc + 1.hour
signed = JOSE::JWT.sign(jwk, jwt)
valid, decoded, header = JOSE::JWT.verify_strict(jwk, ["HS256"], signed,
  iss: "example.com",
  aud: "api")
valid               # => true
decoded["sub"].as_s # => "alice"
header["typ"].as_s  # => "JWT"
```

### JWKS (RFC 7517 §5)

```crystal
require "jose"

# Build a key set from two keys with distinct kids.
k1 = JOSE::JWK.generate_key_ec
k1 = JOSE::JWK.from_map(k1.map.merge({"kid" => JSON::Any.new("sig")}))
k2 = JOSE::JWK.generate_key_oct
k2 = JOSE::JWK.from_map(k2.map.merge({"kid" => JSON::Any.new("enc")}))
jwks = JOSE::JWKS.new([k1, k2])

# Publish only public key material (e.g. as /.well-known/jwks.json).
public_jwks = jwks.to_public
public_jwks.to_binary  # => {"keys":[...]}

# Look up a key by kid during token verification.
key = jwks["sig"]
```

### Load an external key via OpenSSL

```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec-p256.pem
```

```crystal
jwk = JOSE::JWK.from_pem(File.read("ec-p256.pem"))
```

### Password-based encryption (PBES2)

```crystal
require "jose"

# Encrypt using a plain-text password (no key material needed).
# Default: PBES2-HS512+A256KW key-wrap + A256GCM content-encryption.
token = JOSE::JWE.block_encrypt("correct horse battery staple", "secret message")

# Decrypt with the same password.
plaintext = JOSE::JWE.block_decrypt("correct horse battery staple", token)
# => "secret message"
```

### JWS JSON Serialization (RFC 7515 §7.2)

```crystal
require "jose"

jwk = JOSE::JWK.generate_key_oct

# Produce a flattened JWS JSON token.
json_token = JOSE::JWS.sign_json(jwk, %({"sub":"alice"}))

# Verify — works for both flattened and general (multi-signature) form.
valid, payload = JOSE::JWS.verify_json(jwk, json_token)
valid   # => true
payload # => "{\"sub\":\"alice\"}"
```

### JWE JSON Serialization (RFC 7516 §7.2)

```crystal
require "jose"

jwk = JOSE::JWK.generate_key_oct(size: 16)
overrides = JSON.parse({"alg" => "A128KW", "enc" => "A128GCM"}.to_json).as_h

# Encrypt to flattened JSON (optionally pass aad: Bytes for extra auth data).
json_token = JOSE::JWE.json_encrypt(jwk, "hello json", overrides)

# Decrypt — also handles the general form with multiple recipients.
plaintext = JOSE::JWE.json_decrypt(jwk, json_token)
# => "hello json"
```

### JWS Unencoded Payload (RFC 7797)

When `b64: false` is set in the protected header the payload is transmitted
without base64url-encoding. This is useful for webhook or streaming scenarios
where the raw payload text is signed inline. The `crit: ["b64"]` entry is
injected automatically.

> **Compact serialization**: the raw payload must not contain `.` — use JSON
> serialization instead (e.g. for payloads like `$.02`).

```crystal
require "jose"

jwk = JOSE::JWK.generate_key_oct

# ── Compact serialization (payload must not contain '.') ──────────────────────
overrides = {"b64" => JSON::Any.new(false)}
signed = JOSE::JWS.sign(jwk, "hello unencoded", overrides)

# The payload segment is the literal string, not base64url.
signed.peek_protected["b64"].as_bool   # => false
signed.peek_protected["crit"].as_a     # => ["b64"]
signed.peek_payload                    # => "hello unencoded"

valid, payload = JOSE::JWS.verify(jwk, signed)
valid   # => true
payload # => "hello unencoded"

# ── JSON serialization (supports any payload, including '.') ──────────────────
overrides = {"alg" => JSON::Any.new("HS256"), "b64" => JSON::Any.new(false)}
json_token = JOSE::JWS.sign_json(jwk, "$.02", protected_overrides: overrides)

valid, payload = JOSE::JWS.verify_json(jwk, json_token)
valid   # => true
payload # => "$.02"
```

### Detached JWS (RFC 7515 §7)

```crystal
require "jose"

jwk = JOSE::JWK.generate_key_oct
payload = "the payload travels out-of-band"

# Sign normally, then strip the payload segment to produce a detached token.
signed = JOSE::JWS.sign(jwk, payload)
parts = signed.compact.split(".")
detached_token = "#{parts[0]}..#{parts[2]}"   # header..signature

# Verify by supplying the payload separately.
valid, _ = JOSE::JWS.verify(jwk, detached_token, detached: payload)
valid # => true
```

### Supported algorithms

#### JWS signing (alg)

- `HS256`, `HS384`, `HS512` — HMAC (`oct`)
- `ES256`, `ES384`, `ES512` — ECDSA (`EC`)
- `RS256`, `RS384`, `RS512` — RSA PKCS#1 v1.5 (`RSA`)
- `PS256`, `PS384`, `PS512` — RSA PSS (`RSA`)
- `EdDSA` — Ed25519 (`OKP`)

#### JWE key-wrap (alg)

- `dir` — direct symmetric (`oct`)
- `A128KW`, `A192KW`, `A256KW` — AES Key Wrap (`oct`)
- `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` — ECDH (`EC`)
- `RSA-OAEP`, `RSA-OAEP-256`, `RSA1_5` — RSA (`RSA`)
- `A128GCMKW`, `A192GCMKW`, `A256GCMKW` — AES-GCM Key Wrap (`oct`)
- `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` — Password-based (`string`)

#### JWE content-encryption (enc)

- `A128GCM`, `A192GCM`, `A256GCM` — AES-GCM
- `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` — AES-CBC + HMAC

## Development

```sh
shards install
make spec          # run tests
make lint          # ameba static analysis
crystal tool format --check src/ spec/   # format check
```

## Contributing

1. Fork it (<https://github.com/threez/jose/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Vincent Landgraf](https://github.com/threez) — creator and maintainer

## License

MIT — see [LICENSE](LICENSE).
