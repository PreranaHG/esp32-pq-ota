#include "crypto_verify.h"
#include "mbedtls/gcm.h"

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