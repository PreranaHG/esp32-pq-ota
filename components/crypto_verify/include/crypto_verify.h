#ifndef CRYPTO_VERIFY_H
#define CRYPTO_VERIFY_H

#include <stdint.h>
#include <stddef.h>

#define CRYPTO_VERIFY_KEY_BYTES  32  // AES-256
#define CRYPTO_VERIFY_IV_BYTES   12  // 96-bit nonce (GCM recommended size)
#define CRYPTO_VERIFY_TAG_BYTES  16  // 128-bit auth tag

int crypto_verify_aes_gcm_encrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t *tag);

int crypto_verify_aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *iv,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *tag,
    uint8_t *plaintext);

#endif
