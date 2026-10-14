"""Offline function truth from reviewed source registries and explicit kernels.

This is annotation, never a runtime name classifier. Unreviewed functions in
positive files are unknown, not automatically positive or negative.
"""
from pathlib import Path
import json
import re

from .paths import ROOT
from qcs.paths import resource_path
ALGORITHMS = ['AES', 'DES', 'RC4', 'ChaCha20', 'RSA', 'ECDSA', 'ECDH', 'MD5',
              'SHA-1', 'SHA-256', 'SM2', 'SM3', 'SM4']
LEGACY_MANIFESTS = [
    'samples/operation-development-20261013/manifest.json',
    'samples/research-development-20261013/manifest.json',
    'samples/guomi-development-20261012/all-manifest.json',
    'samples/guomi-operations-20261012/manifest.json',
    'samples/semantic-development-20261013/manifest.json',
    'samples/controlflow-development-20261014/manifest.json',
]
MANIFESTS = ['build/datasets/manifests/' + name.replace('/', '__') for name in LEGACY_MANIFESTS]
# Exact or narrowly reviewed source function names. SHA224-shared compression
# helpers are not assigned SHA256 merely because their parent file contains it.
KERNELS = {
    'mbedtls-aes': ['mbedtls_internal_aes_encrypt', 'mbedtls_internal_aes_decrypt', 'mbedtls_aes_setkey_enc', 'mbedtls_aes_setkey_dec'],
    'mbedtls-des': ['mbedtls_des_crypt_ecb', 'mbedtls_des_setkey'],
    'mbedtls-md5': ['mbedtls_internal_md5_process', 'mbedtls_md5_starts', 'mbedtls_md5_finish'],
    'mbedtls-sha1': ['mbedtls_internal_sha1_process', 'mbedtls_sha1_starts', 'mbedtls_sha1_finish'],
    'mbedtls-sha256': ['mbedtls_sha256'],
    'mbedtls-chacha20': ['chacha20_block', 'chacha20_inner_block', 'chacha20_quarter_round', 'mbedtls_chacha20_update'],
    'mbedtls-rsa': ['mbedtls_rsa_public', 'mbedtls_rsa_private'],
    'mbedtls-ecdsa': ['mbedtls_ecdsa_sign_restartable', 'mbedtls_ecdsa_verify_restartable'],
    'mbedtls-ecdh': ['ecdh_compute_shared_restartable', 'ecdh_calc_secret_internal'],
    'arduinolibs-aes': ['AESCommon::encryptBlock', 'AESCommon::decryptBlock', '_ZN9AESCommon12encryptBlockEPhPKh', '_ZN9AESCommon12decryptBlockEPhPKh'],
    'arduinolibs-sha256': ['SHA256::processChunk', 'SHA256::reset', 'SHA256::finalize', '_ZN6SHA25612processChunkEv', '_ZN6SHA2565resetEv', '_ZN6SHA2568finalizeEPvm'],
    'arduinolibs-sha1': ['SHA1::processChunk', 'SHA1::reset', 'SHA1::finalize', '_ZN4SHA112processChunkEv', '_ZN4SHA15resetEv', '_ZN4SHA18finalizeEPvm'],
    'arduinolibs-chacha': ['ChaCha::hashCore', 'ChaCha::keystreamBlock', '_ZN6ChaCha8hashCoreEPjPKjh', '_ZN6ChaCha14keystreamBlockEPj'],
    'arduinolibs-curve25519': ['Curve25519::eval', 'Curve25519::dh2', '_ZN10Curve255194evalEPhPKhS2_', '_ZN10Curve255193dh2EPhS0_'],
    'libecc-sha256': ['sha256_process', 'sha256_init', 'sha256_final'],
    'libecc-sm3': ['sm3_process', 'sm3_init', 'sm3_final'],
    'libecc-ecdsa-common': ['__ecdsa_sign_finalize', '__ecdsa_verify_finalize', '__ecdsa_public_key_from_sig'],
    'libecc-sm2': ['_sm2_sign_finalize', '_sm2_verify_finalize'],
    'libecc-ecdh': ['ecccdh_derive_secret'],
    'nettle-rsa-sign': ['nettle_rsa_compute_root'],
    'libmcrypt-arcfour': ['_mcrypt_set_key', '_mcrypt', '_mdecrypt'],
    'libmcrypt-des': ['_mcrypt_set_key', '_mcrypt', '_mdecrypt'],
    'libmcrypt-rijndael-128': ['_mcrypt_set_key', '_mcrypt', '_mdecrypt'],
    'mhash-sha256_sha224': ['sha256_init', 'sha256_digest'],
    'tinyssh-crypto_hash_sha256': ['blocks', 'crypto_hash_sha256_tinyssh'],
    'tinyssh-crypto_scalarmult_curve25519': ['crypto_scalarmult_curve25519_tinyssh'],
    'tinyssh-crypto_stream_chacha20': ['crypto_stream_chacha20_tinyssh', 'crypto_stream_chacha20_tinyssh_xor'],
    'ippcrypto-rsa': ['gsRSAprv_cipher_crt'],
    'ippcrypto-ecdsa': ['ippsGFpECSignDSA'],
    'ippcrypto-ecdh': ['ippsGFpECSharedSecretDH'],
    'ippcrypto-sm2': ['ippsGFpECSignSM2'],
}
NEGATIVE_UNIT_HINTS = ['mini-gmp', 'limb-', 'modinv', 'modpow', 'generic-limb', 'generic-big',
                       'ordinary', 'table-only', 'retained-tables', 'wrong-', 'missing-', 'disconnected', 'roundless']
OTHER_CRYPTO_HINTS = ['sha224', 'sha512', 'blake2', 'ed25519', 'blowfish', 'twofish']
ORDINARY = {'memcpy', 'memset', 'memcmp', 'memmove', 'bcopy', 'bzero', 'strlen', 'strcpy'}


def ancestry(row):
    p = row.get('project', 'unknown')
    if p in {'openssl', 'boringssl'}: return 'openssl-derived'
    if p in {'gmssl', 'gmssl-modern'} or row.get('family', '').startswith('gmssl'): return 'gmssl'
    if p in {'wolfsm', 'wolfssl'}: return 'wolfssl'
    if p in {'controls', 'reference', 'static-controls', 'authored-EC-controls'}: return 'synthetic-or-reference'
    return p


def registry():
    by_hash = {}
    origins = []
    for relative in ['qcs/rules/source_implementations.json', 'qcs/guomi/source_references.json',
                     'qcs/guomi/development_source_references.json']:
        p = resource_path(relative.removeprefix('qcs/'))
        for r in json.loads(p.read_text())['references']:
            by_hash[r['source']['sha256']] = r['functions']
        origins.append(str(p))
    return by_hash, origins


def annotate(name, row, source_hashes, reviewed):
    truth = set(row['truth']['implementation_contains'])
    family = row['family']
    targets = set()
    bases = []
    for digest in source_hashes:
        if name in reviewed.get(digest, {}):
            targets.update(set(reviewed[digest][name]) & truth)
            bases.append('previously reviewed full-source function registry')
    # Explicit kernels override ambiguity in hash-family compression labels.
    if family in KERNELS and name in KERNELS[family]:
        targets.update(truth); bases.append('explicit source-reviewed kernel or operation root')
    if 'SHA-256' in targets and re.search(r'sha256.*(process|transform|block)', name, re.I):
        shared = row.get('project') in {'mbedtls', 'openssl', 'boringssl', 'bearssl', 'mhash'}
        if shared: targets.remove('SHA-256'); bases.append('shared SHA224/256 compression unassigned')
    if targets:
        return sorted(targets), 1, 'target_crypto', bases
    if name in ORDINARY or name.startswith(('math.', 'compiler_rt.', '__clz', '__ctz', '__popcount', '__bswap', '__div', '__udiv', '__mul', '__ash', '__lshr', '__parity', '__ffs')):
        return [], 0, 'ordinary_runtime', ['named runtime source role; not target algorithm']
    if not truth:
        if any(h in family.lower() for h in OTHER_CRYPTO_HINTS):
            if re.search(r'process|transform|block|encrypt|decrypt|crypt|hash|digest|sha512|sha224|blake2', name, re.I):
                return [], 1, 'other_crypto', ['reviewed operation-name role in predeclared other-crypto source unit']
        if any(h in family.lower() for h in NEGATIVE_UNIT_HINTS) or row.get('project') == 'controls':
            return [], 0, 'generic_math_or_control', ['audited standalone generic math or synthetic non-algorithm unit']
    return [], None, 'unlabeled', ['no function-specific truth; not inherited from containing file']
