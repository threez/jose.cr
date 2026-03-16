require "spec"
require "../src/jose"

def generate_ec_jwk_map(crv = "P-256") : Hash(String, JSON::Any)
  JOSE::JWK.generate_key_ec(crv: crv).map
end

def ec_jwk_with_kid(kid = "k1") : JOSE::JWK
  JOSE::JWK.generate_key_ec.with(kid: kid)
end

def generate_rsa_jwk : JOSE::JWK
  JOSE::JWK.generate_key_rsa
end

def generate_oct_jwk(size = 32) : JOSE::JWK
  JOSE::JWK.generate_key_oct(size: size)
end
