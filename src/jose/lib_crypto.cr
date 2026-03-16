# JOSE-specific OpenSSL bindings.
# Only declares functions/types NOT already present in Crystal's stdlib LibCrypto.
# Uses LibCrypto::Bio*, LibCrypto::BioMethod*, LibCrypto::EVP_MD_CTX, etc. where
# those types are already defined by the stdlib.
# :nodoc:
lib LibCryptoJose
  # ── Type aliases (not in stdlib LibCrypto) ────────────────────────────────
  alias EC_GROUP = Void*
  alias EC_POINT = Void*
  alias BIGNUM = Void*
  alias BN_CTX = Void*
  alias ECDSA_SIG = Void*
  alias EVP_PKEY = Void*
  alias EVP_PKEY_CTX = Void*
  alias RSA = Void*

  # ── EC key operations (ec_key_new_by_curve_name + ec_key_free are in LibCrypto) ─
  fun EC_KEY_generate_key(key : LibCrypto::EC_KEY) : LibC::Int
  fun EC_KEY_get0_group(key : LibCrypto::EC_KEY) : EC_GROUP
  fun EC_KEY_get0_public_key(key : LibCrypto::EC_KEY) : EC_POINT
  fun EC_KEY_set_public_key(key : LibCrypto::EC_KEY, pub : EC_POINT) : LibC::Int
  fun EC_KEY_get0_private_key(key : LibCrypto::EC_KEY) : BIGNUM
  fun EC_KEY_set_private_key(key : LibCrypto::EC_KEY, priv : BIGNUM) : LibC::Int
  fun EC_KEY_get_curve_name(key : LibCrypto::EC_KEY) : LibC::Int

  # ── EC group ──────────────────────────────────────────────────────────────
  fun EC_GROUP_get_curve_name(group : EC_GROUP) : LibC::Int

  # ── EC point operations ───────────────────────────────────────────────────
  fun EC_POINT_new(group : EC_GROUP) : EC_POINT
  fun EC_POINT_free(point : EC_POINT)
  fun EC_POINT_oct2point(group : EC_GROUP, p : EC_POINT, buf : UInt8*, len : LibC::SizeT, ctx : BN_CTX) : LibC::Int
  fun EC_POINT_point2oct(group : EC_GROUP, p : EC_POINT, form : LibC::Int, buf : UInt8*, len : LibC::SizeT, ctx : BN_CTX) : LibC::SizeT

  # ── EVP PKEY derive (ECDH via modern API) ─────────────────────────────────
  fun EVP_PKEY_derive_init(ctx : EVP_PKEY_CTX) : LibC::Int
  fun EVP_PKEY_derive_set_peer(ctx : EVP_PKEY_CTX, peer : EVP_PKEY) : LibC::Int
  fun EVP_PKEY_derive(ctx : EVP_PKEY_CTX, key : UInt8*, keylen : LibC::SizeT*) : LibC::Int

  # ── BIGNUM ────────────────────────────────────────────────────────────────
  fun BN_new : BIGNUM
  fun BN_free(a : BIGNUM)
  fun BN_bin2bn(s : UInt8*, len : LibC::Int, ret : BIGNUM) : BIGNUM
  fun BN_bn2bin(a : BIGNUM, to : UInt8*) : LibC::Int
  fun BN_num_bits(a : BIGNUM) : LibC::Int
  fun BN_set_word(a : BIGNUM, w : LibC::ULong) : LibC::Int

  # ── ECDSA signature ───────────────────────────────────────────────────────
  fun ECDSA_SIG_new : ECDSA_SIG
  fun ECDSA_SIG_free(sig : ECDSA_SIG)
  fun ECDSA_SIG_get0(sig : ECDSA_SIG, pr : BIGNUM*, ps : BIGNUM*)
  fun ECDSA_SIG_set0(sig : ECDSA_SIG, r : BIGNUM, s : BIGNUM) : LibC::Int
  fun i2d_ECDSA_SIG(sig : ECDSA_SIG, pp : UInt8**) : LibC::Int
  fun d2i_ECDSA_SIG(sig : ECDSA_SIG*, pp : UInt8**, len : LibC::Long) : ECDSA_SIG

  # ── EVP PKEY ──────────────────────────────────────────────────────────────
  fun EVP_PKEY_new : EVP_PKEY
  fun EVP_PKEY_free(pkey : EVP_PKEY)
  fun EVP_PKEY_set1_EC_KEY(pkey : EVP_PKEY, key : LibCrypto::EC_KEY) : LibC::Int
  fun EVP_PKEY_set1_RSA(pkey : EVP_PKEY, rsa : RSA) : LibC::Int

  # ── EVP PKEY CTX ──────────────────────────────────────────────────────────
  fun EVP_PKEY_CTX_new(pkey : EVP_PKEY, engine : Void*) : EVP_PKEY_CTX
  fun EVP_PKEY_CTX_free(ctx : EVP_PKEY_CTX)
  fun EVP_PKEY_encrypt_init(ctx : EVP_PKEY_CTX) : LibC::Int
  fun EVP_PKEY_encrypt(ctx : EVP_PKEY_CTX, out_buf : UInt8*, outlen : LibC::SizeT*, in_data : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun EVP_PKEY_decrypt_init(ctx : EVP_PKEY_CTX) : LibC::Int
  fun EVP_PKEY_decrypt(ctx : EVP_PKEY_CTX, out_buf : UInt8*, outlen : LibC::SizeT*, in_data : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun EVP_PKEY_CTX_ctrl(ctx : EVP_PKEY_CTX, keytype : LibC::Int, optype : LibC::Int, cmd : LibC::Int, p1 : LibC::Int, p2 : Void*) : LibC::Int

  {% if compare_versions(LibCrypto::OPENSSL_VERSION, "3.0.0") >= 0 %}
    fun EVP_PKEY_CTX_set_rsa_padding(ctx : EVP_PKEY_CTX, pad : LibC::Int) : LibC::Int
    fun EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx : EVP_PKEY_CTX, len : LibC::Int) : LibC::Int
  {% end %}

  # ── EVP DigestSign / DigestVerify (EVP_DigestUpdate reuses LibCrypto.evp_digestupdate) ─
  fun EVP_DigestSignInit(ctx : LibCrypto::EVP_MD_CTX, pctx : EVP_PKEY_CTX*, type : LibCrypto::EVP_MD, engine : Void*, pkey : EVP_PKEY) : LibC::Int
  fun EVP_DigestSignFinal(ctx : LibCrypto::EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*) : LibC::Int
  fun EVP_DigestVerifyInit(ctx : LibCrypto::EVP_MD_CTX, pctx : EVP_PKEY_CTX*, type : LibCrypto::EVP_MD, engine : Void*, pkey : EVP_PKEY) : LibC::Int
  fun EVP_DigestVerifyFinal(ctx : LibCrypto::EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT) : LibC::Int

  # ── AES-GCM raw encrypt/decrypt (stdlib uses CipherInit_ex / CipherUpdate, not Encrypt*) ─
  fun EVP_aes_128_gcm : LibCrypto::EVP_CIPHER
  fun EVP_aes_192_gcm : LibCrypto::EVP_CIPHER
  fun EVP_aes_256_gcm : LibCrypto::EVP_CIPHER
  fun EVP_EncryptInit_ex(ctx : LibCrypto::EVP_CIPHER_CTX, type : LibCrypto::EVP_CIPHER, engine : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun EVP_EncryptUpdate(ctx : LibCrypto::EVP_CIPHER_CTX, out_buf : UInt8*, outl : LibC::Int*, in_data : UInt8*, inl : LibC::Int) : LibC::Int
  fun EVP_EncryptFinal_ex(ctx : LibCrypto::EVP_CIPHER_CTX, out_buf : UInt8*, outl : LibC::Int*) : LibC::Int
  fun EVP_DecryptInit_ex(ctx : LibCrypto::EVP_CIPHER_CTX, type : LibCrypto::EVP_CIPHER, engine : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun EVP_DecryptUpdate(ctx : LibCrypto::EVP_CIPHER_CTX, out_buf : UInt8*, outl : LibC::Int*, in_data : UInt8*, inl : LibC::Int) : LibC::Int
  fun EVP_DecryptFinal_ex(ctx : LibCrypto::EVP_CIPHER_CTX, out_buf : UInt8*, outl : LibC::Int*) : LibC::Int
  fun EVP_CIPHER_CTX_ctrl(ctx : LibCrypto::EVP_CIPHER_CTX, type : LibC::Int, arg : LibC::Int, ptr : Void*) : LibC::Int

  # ── RSA ───────────────────────────────────────────────────────────────────
  fun RSA_new : RSA
  fun RSA_free(rsa : RSA)
  fun RSA_generate_key_ex(rsa : RSA, bits : LibC::Int, e : BIGNUM, cb : Void*) : LibC::Int
  fun RSA_size(rsa : RSA) : LibC::Int
  fun RSA_set0_key(rsa : RSA, n : BIGNUM, e : BIGNUM, d : BIGNUM) : LibC::Int
  fun RSA_set0_factors(rsa : RSA, p : BIGNUM, q : BIGNUM) : LibC::Int
  fun RSA_set0_crt_params(rsa : RSA, dmp1 : BIGNUM, dmq1 : BIGNUM, iqmp : BIGNUM) : LibC::Int
  fun RSA_get0_n(rsa : RSA) : BIGNUM
  fun RSA_get0_e(rsa : RSA) : BIGNUM
  fun RSA_get0_d(rsa : RSA) : BIGNUM
  fun RSA_get0_p(rsa : RSA) : BIGNUM
  fun RSA_get0_q(rsa : RSA) : BIGNUM
  fun RSA_get0_dmp1(rsa : RSA) : BIGNUM
  fun RSA_get0_dmq1(rsa : RSA) : BIGNUM
  fun RSA_get0_iqmp(rsa : RSA) : BIGNUM
  fun RSA_public_encrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : RSA, padding : LibC::Int) : LibC::Int
  fun RSA_private_decrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : RSA, padding : LibC::Int) : LibC::Int
  fun RSA_private_encrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : RSA, padding : LibC::Int) : LibC::Int
  fun RSA_public_decrypt(flen : LibC::Int, from : UInt8*, to : UInt8*, rsa : RSA, padding : LibC::Int) : LibC::Int

  # ── BIO (BIO_new and BIO_free are in LibCrypto; we add mem_buf, s_mem, read, ctrl, PEM) ─
  fun BIO_new_mem_buf(buf : Void*, len : LibC::Int) : LibCrypto::Bio*
  fun BIO_s_mem : LibCrypto::BioMethod*
  fun BIO_read(bio : LibCrypto::Bio*, data : UInt8*, dlen : LibC::Int) : LibC::Int
  fun BIO_ctrl(bio : LibCrypto::Bio*, cmd : LibC::Int, larg : LibC::Long, parg : Void*) : LibC::Long

  # ── PEM ───────────────────────────────────────────────────────────────────
  fun PEM_read_bio_RSAPrivateKey(bp : LibCrypto::Bio*, x : RSA*, cb : Void*, u : Void*) : RSA
  fun PEM_read_bio_RSA_PUBKEY(bp : LibCrypto::Bio*, x : RSA*, cb : Void*, u : Void*) : RSA
  fun PEM_write_bio_RSAPrivateKey(bp : LibCrypto::Bio*, rsa : RSA, enc : LibCrypto::EVP_CIPHER, kstr : UInt8*, klen : LibC::Int, cb : Void*, u : Void*) : LibC::Int
  fun PEM_write_bio_RSA_PUBKEY(bp : LibCrypto::Bio*, rsa : RSA) : LibC::Int
  fun PEM_read_bio_ECPrivateKey(bp : LibCrypto::Bio*, key : LibCrypto::EC_KEY*, cb : Void*, u : Void*) : LibCrypto::EC_KEY
  fun PEM_read_bio_EC_PUBKEY(bp : LibCrypto::Bio*, key : LibCrypto::EC_KEY*, cb : Void*, u : Void*) : LibCrypto::EC_KEY
  fun PEM_write_bio_ECPrivateKey(bp : LibCrypto::Bio*, key : LibCrypto::EC_KEY, enc : LibCrypto::EVP_CIPHER, kstr : UInt8*, klen : LibC::Int, cb : Void*, u : Void*) : LibC::Int
  fun PEM_write_bio_EC_PUBKEY(bp : LibCrypto::Bio*, key : LibCrypto::EC_KEY) : LibC::Int

  # ── Constants (NID_X9_62_prime256v1 = 415 is in LibCrypto) ───────────────
  NID_secp384r1                 = 715
  NID_secp521r1                 = 716
  POINT_CONVERSION_UNCOMPRESSED =   4

  EVP_CTRL_AEAD_SET_IVLEN =  0x9
  EVP_CTRL_AEAD_GET_TAG   = 0x10
  EVP_CTRL_AEAD_SET_TAG   = 0x11

  RSA_PKCS1_PADDING      = 1
  RSA_NO_PADDING         = 3
  RSA_PKCS1_OAEP_PADDING = 4
  RSA_PKCS1_PSS_PADDING  = 6

  EVP_PKEY_RSA                  = 6
  EVP_PKEY_OP_ENCRYPT           = (1 << 6)
  EVP_PKEY_OP_DECRYPT           = (1 << 7)
  EVP_PKEY_CTRL_RSA_PADDING     = 0x1001
  EVP_PKEY_CTRL_RSA_OAEP_MD     = 0x1009
  EVP_PKEY_CTRL_RSA_MGF1_MD     = 0x1005
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = 0x1004

  BIO_CTRL_INFO    =  3
  BIO_CTRL_PENDING = 10

  # ── PBKDF2 ────────────────────────────────────────────────────────────────
  fun PKCS5_PBKDF2_HMAC(pass : UInt8*, passlen : LibC::Int, salt : UInt8*, saltlen : LibC::Int,
                        iter : LibC::Int, digest : LibCrypto::EVP_MD,
                        keylen : LibC::Int, out : UInt8*) : LibC::Int
end
