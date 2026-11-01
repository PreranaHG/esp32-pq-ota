#ifndef OTA_HTTP_DOWNLOAD_H
#define OTA_HTTP_DOWNLOAD_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_client.h"
#include "mlkem_native.h"
#include "mldsa_native.h"
#include "crypto_verify.h"

/*
 * Bundle layout on the wire (adjust to match docs/format-spec.md):
 *
 *   [ ct_kem   : MLKEM_CIPHERTEXTBYTES(512) ]  ML-KEM-512 ciphertext
 *   [ sig      : MLDSA44_BYTES              ]  ML-DSA-44 signature over SHA-256(plaintext)
 *   [ tag      : CRYPTO_VERIFY_TAG_BYTES    ]  AES-GCM auth tag
 *   [ length   : 4 bytes, little-endian     ]  ciphertext length
 *   [ ciphertext : length bytes             ]  <-- streamed by the caller, never buffered whole
 */

// Sanity cap against a corrupt/hostile content-length. Not a RAM limit
// anymore, since the ciphertext is streamed and written in small chunks —
// this just guards against an absurd length field.
#define OTA_MAX_CIPHERTEXT_BYTES (4 * 1024 * 1024)

typedef struct {
    uint8_t  ct_kem[MLKEM_CIPHERTEXTBYTES(512)];
    uint8_t  sig[MLDSA44_BYTES];
    uint8_t  tag[CRYPTO_VERIFY_TAG_BYTES];
    size_t   ciphertext_len;
    esp_http_client_handle_t client;  // left OPEN, positioned at the start of the ciphertext bytes
} ota_bundle_stream_t;

/*
 * Connects, downloads and validates the fixed-size bundle header (ct_kem,
 * sig, tag, length), and leaves the HTTP connection open, positioned
 * exactly at the start of the ciphertext bytes.
 *
 * The caller must then read exactly out->ciphertext_len bytes from
 * out->client (in whatever chunk size it likes, via ota_http_read_exact()),
 * and finally call ota_bundle_stream_close() to release the connection.
 */
esp_err_t ota_download_bundle_header(const char *url, ota_bundle_stream_t *out);

/* Reads exactly `len` bytes from an open esp_http_client stream, handling
 * the fact that esp_http_client_read() may return fewer bytes than asked. */
esp_err_t ota_http_read_exact(esp_http_client_handle_t client, uint8_t *dst, size_t len);

/* Closes and cleans up the HTTP connection opened by ota_download_bundle_header(). */
void ota_bundle_stream_close(ota_bundle_stream_t *stream);

#endif // OTA_HTTP_DOWNLOAD_H