#include "crypto_verify.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

int crypto_verify_aes_gcm_encrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t *tag)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, CRYPTO_VERIFY_KEY_BYTES * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT,
        plaintext_len,
        iv, CRYPTO_VERIFY_IV_BYTES,
        NULL, 0,
        plaintext, ciphertext,
        CRYPTO_VERIFY_TAG_BYTES, tag);

    mbedtls_gcm_free(&ctx);
    return ret;
}

int crypto_verify_aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, CRYPTO_VERIFY_KEY_BYTES * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(
        &ctx,
        ciphertext_len,
        iv, CRYPTO_VERIFY_IV_BYTES,
        NULL, 0,
        tag, CRYPTO_VERIFY_TAG_BYTES,
        ciphertext, plaintext);

    mbedtls_gcm_free(&ctx);
    return ret;
}
int crypto_verify_derive_aes_key(
    const uint8_t *shared_secret, size_t shared_secret_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out_key)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return -1;
    }

    // No salt: pass NULL/0, per HKDF spec (treated as a string of zero-valued bytes)
    return mbedtls_hkdf(
        md_info,
        NULL, 0,                          // salt
        shared_secret, shared_secret_len, // IKM
        info, info_len,                   // info (domain separation)
        out_key, CRYPTO_VERIFY_KEY_BYTES  // OKM (32 bytes, AES-256 key)
    );
}