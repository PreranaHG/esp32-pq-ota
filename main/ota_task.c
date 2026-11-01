#include <string.h>
#include "esp_timer.h"
#include "esp_system.h"
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "mlkem_native.h"
#include "mldsa_native.h"
#include "crypto_verify.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "wifi_init.h"
#include "ota_http_download.h"
#include "pqc_keys.h"
#include "ota_task.h"

static const char *TAG = "ota_task";

// Keep whatever you already have set here (real SSID/password/IP) — don't
// overwrite them with these placeholders when you copy this file in.
#define FIRMWARE_URL   "http://10.182.242.58:8080/firmware" // <-- your dev machine's LAN IP
#define WIFI_SSID      "Bhawna"                          // <-- your Wi-Fi SSID
#define WIFI_PASSWORD  "bhawna220"                      // <-- your Wi-Fi password

// Chunk size for streaming decrypt + flash write. RAM usage stays flat at
// roughly 2x this value regardless of firmware size — unlike buffering the
// whole image, which scaled with firmware size and didn't fit in ~320KB RAM.
#define OTA_CHUNK_SIZE 4096

// Constant-time buffer compare, so a tag mismatch doesn't leak timing info
// about how many leading bytes matched.
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff; // 0 => equal
}

static void ota_download_and_apply_task(void *pvParameters)
{
    ESP_ERROR_CHECK(wifi_init_sta(WIFI_SSID, WIFI_PASSWORD));

    int64_t t_start = esp_timer_get_time();
    int64_t t0, t_kem_us = 0, t_hkdf_us = 0, t_stream_us = 0,
            t_tag_us = 0, t_sig_us = 0, t_finish_us = 0;
    const char *kem_status = "NOT RUN", *tag_status = "NOT RUN", *sig_status = "NOT RUN";

    ota_bundle_stream_t stream;
    esp_err_t err = ota_download_bundle_header(FIRMWARE_URL, &stream);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Bundle header download failed: %s", esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }
    int64_t t_header_us = esp_timer_get_time() - t_start;

    // --- ML-KEM decapsulation ---
    uint8_t shared_secret[MLKEM_BYTES];
    t0 = esp_timer_get_time();
    int kem_ret = PQCP_MLKEM_NATIVE_MLKEM512_dec(shared_secret, stream.ct_kem, pqc_get_kem_sk());
    t_kem_us = esp_timer_get_time() - t0;
    if (kem_ret != 0) {
        ESP_LOGE(TAG, "FAILURE: ML-KEM-512 decapsulation failed (%d)", kem_ret);
        ota_bundle_stream_close(&stream);
        vTaskDelete(NULL);
        return;
    }
    kem_status = "OK";
    ESP_LOGI(TAG, "ML-KEM-512 decapsulation OK (%lld us)", (long long)t_kem_us);

    // --- HKDF -> AES key ---
    uint8_t aes_key[CRYPTO_VERIFY_KEY_BYTES];
    static const uint8_t hkdf_info[] = "esp32-pq-ota-aes-key-v1";
    t0 = esp_timer_get_time();
    crypto_verify_derive_aes_key(shared_secret, sizeof(shared_secret),
                                 hkdf_info, sizeof(hkdf_info) - 1, aes_key);
    t_hkdf_us = esp_timer_get_time() - t0;

    uint8_t iv[CRYPTO_VERIFY_IV_BYTES];
    memset(iv, 0x13, sizeof(iv));

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, CRYPTO_VERIFY_KEY_BYTES * 8) != 0 ||
        mbedtls_gcm_starts(&gcm, MBEDTLS_GCM_DECRYPT, iv, sizeof(iv)) != 0) {
        ESP_LOGE(TAG, "Failed to start AES-GCM stream");
        mbedtls_gcm_free(&gcm);
        ota_bundle_stream_close(&stream);
        vTaskDelete(NULL);
        return;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    esp_ota_handle_t ota_handle = 0;
    bool ota_started = false;

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition) {
        ESP_LOGE(TAG, "No OTA update partition available");
        goto cleanup_fail;
    }

    {
        esp_err_t e = esp_ota_begin(update_partition, stream.ciphertext_len, &ota_handle);
        if (e != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(e));
            goto cleanup_fail;
        }
        ota_started = true;
    }

    // --- Stream: download + AES-GCM decrypt + SHA-256 + flash write ---
    {
        static uint8_t in_buf[OTA_CHUNK_SIZE];
        static uint8_t out_buf[OTA_CHUNK_SIZE];
        size_t remaining = stream.ciphertext_len;

        t0 = esp_timer_get_time();
        while (remaining > 0) {
            size_t chunk = remaining < OTA_CHUNK_SIZE ? remaining : OTA_CHUNK_SIZE;

            if (ota_http_read_exact(stream.client, in_buf, chunk) != ESP_OK) {
                ESP_LOGE(TAG, "Ciphertext stream read failed");
                goto cleanup_fail;
            }
            size_t out_len = 0;
            if (mbedtls_gcm_update(&gcm, in_buf, chunk, out_buf, sizeof(out_buf), &out_len) != 0) {
                ESP_LOGE(TAG, "AES-GCM update failed");
                goto cleanup_fail;
            }
            mbedtls_sha256_update(&sha, out_buf, out_len);
            if (esp_ota_write(ota_handle, out_buf, out_len) != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write failed");
                goto cleanup_fail;
            }
            remaining -= chunk;
        }
        t_stream_us = esp_timer_get_time() - t0;
        ESP_LOGI(TAG, "Streamed and wrote %zu decrypted bytes", stream.ciphertext_len);
    }

    // --- AES-GCM tag check ---
    {
        uint8_t computed_tag[CRYPTO_VERIFY_TAG_BYTES];
        size_t final_len = 0;
        t0 = esp_timer_get_time();
        mbedtls_gcm_finish(&gcm, NULL, 0, &final_len, computed_tag, sizeof(computed_tag));
        int diff = ct_memcmp(computed_tag, stream.tag, sizeof(computed_tag));
        t_tag_us = esp_timer_get_time() - t0;
        if (diff != 0) {
            tag_status = "FAILED";
            ESP_LOGE(TAG, "FAILURE: AES-GCM auth tag mismatch — refusing to boot this image");
            goto cleanup_fail;
        }
        tag_status = "OK";
        ESP_LOGI(TAG, "AES-GCM tag verified");
    }

    // --- ML-DSA-44 signature check ---
    {
        uint8_t hash[32];
        mbedtls_sha256_finish(&sha, hash);

        t0 = esp_timer_get_time();
        int vr = mldsa44_verify(stream.sig, hash, sizeof(hash), NULL, 0, pqc_get_dsa_pk());
        t_sig_us = esp_timer_get_time() - t0;
        if (vr != 0) {
            sig_status = "FAILED";
            ESP_LOGE(TAG, "FAILURE: ML-DSA-44 signature verification failed — refusing to flash");
            goto cleanup_fail;
        }
        sig_status = "OK";
        ESP_LOGI(TAG, "ML-DSA-44 signature verified");
    }

    // --- Finalize image and switch boot partition ---
    t0 = esp_timer_get_time();
    {
        esp_err_t e2 = esp_ota_end(ota_handle);
        if (e2 != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(e2));
            ota_started = false;
            goto cleanup_fail;
        }
    }
    if (esp_ota_set_boot_partition(update_partition) != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed");
        goto cleanup_close;
    }
    t_finish_us = esp_timer_get_time() - t0;

    // --- Summary ---
    {
        size_t fw_bytes = stream.ciphertext_len;
        size_t overhead = MLKEM_CIPHERTEXTBYTES(512) + MLDSA44_BYTES + CRYPTO_VERIFY_TAG_BYTES + 4;
        size_t bundle_bytes = fw_bytes + overhead;
        int64_t total_us = esp_timer_get_time() - t_start;

        printf("\n================ OTA SUMMARY ================\n");
        printf("Firmware size : %u bytes\n", (unsigned)fw_bytes);
        printf("Bundle size   : %u bytes\n", (unsigned)bundle_bytes);
        printf("Overhead      : %u bytes (%d KEM ciphertext, %d signature, %d tag, 4 length)\n",
               (unsigned)overhead, (int)MLKEM_CIPHERTEXTBYTES(512), (int)MLDSA44_BYTES,
               (int)CRYPTO_VERIFY_TAG_BYTES);
        printf("ML-KEM-512 decapsulation : %s (%lld us)\n", kem_status, (long long)t_kem_us);
        printf("HKDF-SHA256 key derive   : OK (%lld us)\n", (long long)t_hkdf_us);
        printf("AES-GCM tag verified     : %s (%lld us final tag check)\n", tag_status, (long long)t_tag_us);
        printf("ML-DSA-44 signature      : %s (%lld us, %.2f ms)\n", sig_status,
               (long long)t_sig_us, t_sig_us / 1000.0);
        printf("Header download          : %.2f s\n", t_header_us / 1e6);
        printf("Download+decrypt+flash   : %.2f s\n", t_stream_us / 1e6);
        printf("Image validate + switch  : %.2f s\n", t_finish_us / 1e6);
        printf("Total OTA time           : %.2f s\n", total_us / 1e6);
        printf("Free heap now            : %u bytes\n", (unsigned)esp_get_free_heap_size());
        printf("Min free heap (peak use) : %u bytes\n", (unsigned)esp_get_minimum_free_heap_size());
        printf("Task stack high-water    : %u bytes free\n",
               (unsigned)uxTaskGetStackHighWaterMark(NULL));
        printf("=============================================\n\n");
        fflush(stdout);
    }

    mbedtls_gcm_free(&gcm);
    mbedtls_sha256_free(&sha);
    ota_bundle_stream_close(&stream);

    ESP_LOGI(TAG, "OTA update applied — rebooting");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

cleanup_fail:
    if (ota_started) {
        esp_ota_abort(ota_handle);
    }
cleanup_close:
    mbedtls_gcm_free(&gcm);
    mbedtls_sha256_free(&sha);
    ota_bundle_stream_close(&stream);
    vTaskDelete(NULL);
}

void ota_task_start(void)
{
    BaseType_t result = xTaskCreate(ota_download_and_apply_task, "ota_download_apply",
                                     65536, NULL, 5, NULL);
    if (result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create ota_download_apply_task");
    }
}