"""Our API mappings, checked against OpenSSL 3 and mbedTLS 2/3 headers.

This is an independent Python implementation, not a claim about original qryx.
Full symbol names must match these allowlists; generic EC/EVP/BN are clues.
"""
import re
import json
from pathlib import Path

API = {}

def add(algorithm, names):
    for name in names.split():
        API[name] = algorithm

add("AES", "AES_set_encrypt_key AES_set_decrypt_key AES_encrypt AES_decrypt AES_ecb_encrypt AES_cbc_encrypt AES_cfb128_encrypt AES_ofb128_encrypt AES_ctr128_encrypt AES_ige_encrypt mbedtls_aes_setkey_enc mbedtls_aes_setkey_dec mbedtls_aes_crypt_ecb mbedtls_aes_crypt_cbc mbedtls_aes_crypt_cfb128 mbedtls_aes_crypt_cfb8 mbedtls_aes_crypt_ofb mbedtls_aes_crypt_ctr mbedtls_aes_crypt_xts mbedtls_aes_xts_setkey_enc mbedtls_aes_xts_setkey_dec")
add("DES", "DES_set_key DES_set_key_checked DES_set_key_unchecked DES_ecb_encrypt DES_ncbc_encrypt DES_cfb_encrypt DES_ofb_encrypt mbedtls_des_setkey_enc mbedtls_des_setkey_dec mbedtls_des_crypt_ecb mbedtls_des_crypt_cbc")
add("3DES", "DES_ecb3_encrypt DES_ede3_cbc_encrypt mbedtls_des3_set2key_enc mbedtls_des3_set2key_dec mbedtls_des3_set3key_enc mbedtls_des3_set3key_dec mbedtls_des3_crypt_ecb mbedtls_des3_crypt_cbc")
add("RC4", "RC4 RC4_set_key mbedtls_arc4_setup mbedtls_arc4_crypt")
add("ChaCha20", "mbedtls_chacha20_setkey mbedtls_chacha20_starts mbedtls_chacha20_update mbedtls_chacha20_crypt mbedtls_chachapoly_setkey mbedtls_chachapoly_encrypt_and_tag mbedtls_chachapoly_auth_decrypt")
add("RSA", "RSA_new RSA_generate_key_ex RSA_public_encrypt RSA_private_decrypt RSA_private_encrypt RSA_public_decrypt RSA_sign RSA_verify RSA_size RSA_free mbedtls_rsa_gen_key mbedtls_rsa_pkcs1_encrypt mbedtls_rsa_pkcs1_decrypt mbedtls_rsa_pkcs1_sign mbedtls_rsa_pkcs1_verify mbedtls_rsa_rsaes_pkcs1_v15_encrypt mbedtls_rsa_rsaes_pkcs1_v15_decrypt mbedtls_rsa_rsaes_oaep_encrypt mbedtls_rsa_rsaes_oaep_decrypt mbedtls_rsa_rsassa_pss_sign mbedtls_rsa_rsassa_pss_verify mbedtls_rsa_public mbedtls_rsa_private")
add("ECDSA", "ECDSA_sign ECDSA_sign_ex ECDSA_verify ECDSA_do_sign ECDSA_do_verify ECDSA_size mbedtls_ecdsa_genkey mbedtls_ecdsa_sign mbedtls_ecdsa_sign_det mbedtls_ecdsa_sign_det_ext mbedtls_ecdsa_verify mbedtls_ecdsa_write_signature mbedtls_ecdsa_read_signature")
add("ECDH", "ECDH_compute_key mbedtls_ecdh_gen_public mbedtls_ecdh_compute_shared mbedtls_ecdh_calc_secret mbedtls_ecdh_make_public mbedtls_ecdh_read_public mbedtls_ecdh_setup")
add("DH", "DH_new DH_generate_key DH_compute_key DH_compute_key_padded DH_generate_parameters_ex mbedtls_dhm_make_params mbedtls_dhm_make_public mbedtls_dhm_read_public mbedtls_dhm_calc_secret")
add("DSA", "DSA_new DSA_sign DSA_verify DSA_do_sign DSA_do_verify DSA_generate_key")
add("MD5", "MD5 MD5_Init MD5_Update MD5_Final mbedtls_md5 mbedtls_md5_ret mbedtls_md5_starts mbedtls_md5_starts_ret mbedtls_md5_update mbedtls_md5_update_ret mbedtls_md5_finish mbedtls_md5_finish_ret")
add("SHA-1", "SHA1 SHA1_Init SHA1_Update SHA1_Final mbedtls_sha1 mbedtls_sha1_ret mbedtls_sha1_starts mbedtls_sha1_starts_ret mbedtls_sha1_update mbedtls_sha1_update_ret mbedtls_sha1_finish mbedtls_sha1_finish_ret")
# sha256_starts and one-shot take is224; they are handled as ambiguous without arguments.
add("SHA-256", "SHA256 SHA256_Init SHA256_Update SHA256_Final")
add("HMAC", "HMAC HMAC_Init_ex HMAC_Update HMAC_Final")
add("HMAC", "mbedtls_md_hmac mbedtls_md_hmac_starts mbedtls_md_hmac_update mbedtls_md_hmac_finish mbedtls_md_hmac_reset")
add("Base64", "EVP_EncodeBlock EVP_DecodeBlock mbedtls_base64_encode mbedtls_base64_decode")

for bits in (128, 192, 256):
    for mode in ("ecb", "cbc", "cfb", "cfb1", "cfb8", "cfb128", "ofb", "ctr", "gcm", "ccm", "xts", "wrap", "wrap_pad", "ocb"):
        if mode != "xts" or bits != 192:
            API[f"EVP_aes_{bits}_{mode}"] = "AES"
add("DES", "EVP_des_ecb EVP_des_cbc EVP_des_cfb EVP_des_cfb64 EVP_des_ofb")
add("3DES", "EVP_des_ede EVP_des_ede3 EVP_des_ede_cbc EVP_des_ede3_cbc")
add("RC4", "EVP_rc4 EVP_rc4_40 EVP_rc4_hmac_md5")
add("ChaCha20", "EVP_chacha20 EVP_chacha20_poly1305")
add("MD5", "EVP_md5")
add("SHA-1", "EVP_sha1")
add("SHA-256", "EVP_sha256")
add("SHA-512", "EVP_sha512")
# AES_ctr128_encrypt is a historical/internal name, not a public OpenSSL 3.2 API.
API.pop("AES_ctr128_encrypt", None)
add("RSA", "EVP_PKEY_get0_RSA EVP_PKEY_get1_RSA EVP_PKEY_CTX_set_rsa_keygen_bits EVP_PKEY_CTX_set_rsa_padding EVP_PKEY_CTX_set_rsa_pss_saltlen")

# Exact terminal-library interfaces, pinned and audited separately from labels.
from .paths import resource_path
TERMINAL_RULES_PATH = resource_path('rules/terminal_api_mapping.json')
TERMINAL_RULES = json.loads(TERMINAL_RULES_PATH.read_text(encoding="utf-8"))
API.update({name: rule['algorithm'] for name, rule in TERMINAL_RULES['rules'].items()})
MULTI_API = TERMINAL_RULES['multi_algorithm_apis']
API.update({name: algorithms[0] for name, algorithms in MULTI_API.items()})
from .guomi import API as GUOMI_API
API.update(GUOMI_API)

SELECTORS = {"EVP_CIPHER_fetch": {"AES": "AES", "DES": "DES", "DES-EDE3": "3DES", "RC4": "RC4", "CHACHA20": "ChaCha20", "CHACHA20-POLY1305": "ChaCha20"},
             "EVP_MD_fetch": {"MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512"},
             "EVP_PKEY_CTX_new_id": {"EVP_PKEY_RSA": "RSA", "EVP_PKEY_DSA": "DSA", "EVP_PKEY_DH": "DH", "EVP_PKEY_ED25519": "Ed25519"}}
SELECTORS['EVP_CIPHER_fetch'].update({name:'SM4' for name in ('SM4-ECB','SM4-CBC','SM4-CTR','SM4-CFB','SM4-OFB')})
SELECTORS['EVP_MD_fetch']['SM3'] = 'SM3'
SELECTORS['EVP_PKEY_CTX_new_id']['EVP_PKEY_SM2'] = 'SM2'

def normalize_symbol(name):
    name = name.split("@", 1)[0]
    return name.removeprefix("__imp_").removeprefix("_")

def classify(name):
    name = normalize_symbol(name)
    if name in API:
        return API[name], None
    if name.startswith(("EC_", "ECDH_", "ECDSA_", "mbedtls_ecp_")):
        return None, "elliptic_curve_generic"
    if name.startswith(("BN_", "EVP_", "mbedtls_pk_", "mbedtls_cipher_", "mbedtls_md_", "mbedtls_gcm_", "mbedtls_ccm_")):
        return None, "crypto_generic"
    if name.startswith("mbedtls_sha256"):
        return None, "SHA-224/SHA-256"
    if name.startswith(("br_ec_", "uECC_", "ecc_")):
        return None, "elliptic_curve_generic"
    return None, None

TOKEN = re.compile(r"\b(?:sm[234]_\w+|AES\w*|DES\w*|RSA\w*|ECDSA\w*|ECDH\w*|DH_\w+|DSA\w*|EC_\w+|BN_\w+|EVP_\w+|RC4\w*|SHA\w*|MD5\w*|HMAC\w*|mbedtls_\w+|br_\w+|tc_\w+|uECC_\w+|gx(?:aes|md5|sha1|sha256|ecdsa)_\w+|ecc_\w+|sha_256_\w+|esp_rom_md5_\w+)\b")
