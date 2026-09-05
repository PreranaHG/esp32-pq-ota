#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mlkem_native.h"
#include "mldsa_native.h"
#include "crypto_verify.h"
#include "aes_gcm_demo.h"

static const char *TAG = "pqc_ota";

static void mldsa_test_task(void *pvParameters)
{
    uint8_t pk[MLDSA44_PUBLICKEYBYTES];
    uint8_t sk[MLDSA44_SECRETKEYBYTES];
    uint8_t sig[MLDSA44_BYTES];
    const uint8_t msg[] = "esp32-pq-ota test message";
    size_t msglen = sizeof(msg);

    ESP_LOGI(TAG, "Generating ML-DSA-44 keypair...");
    mldsa44_keypair(pk, sk);

    ESP_LOGI(TAG, "Signing message...");
    mldsa44_signature(sig, msg, msglen, NULL, 0, sk);

    ESP_LOGI(TAG, "Verifying signature...");
    int ok = mldsa44_verify(sig, msg, msglen, NULL, 0, pk);

    if (ok == 0) {
        ESP_LOGI(TAG, "SUCCESS: ML-DSA-44 signature verified!");
    } else {
        ESP_LOGE(TAG, "FAILURE: ML-DSA-44 signature did not verify");
    }

    sig[0] ^= 0xFF;
    int tampered = mldsa44_verify(sig, msg, msglen, NULL, 0, pk);
    if (tampered != 0) {
        ESP_LOGI(TAG, "SUCCESS: tampered signature correctly rejected!");
    } else {
        ESP_LOGE(TAG, "FAILURE: tampered signature was accepted (should not happen)");
    }

    vTaskDelete(NULL);
}

static void aes_gcm_test_task(void *pvParameters)
{
    uint8_t key[CRYPTO_VERIFY_KEY_BYTES];
    uint8_t iv[CRYPTO_VERIFY_IV_BYTES];
    const uint8_t plaintext[] = "esp32-pq-ota AES-GCM test message";
    size_t len = sizeof(plaintext);

    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    uint8_t tag[CRYPTO_VERIFY_TAG_BYTES];

    memset(key, 0xAB, sizeof(key));
    memset(iv, 0xCD, sizeof(iv));

    ESP_LOGI(TAG, "AES-GCM: encrypting...");
    int ret = crypto_verify_aes_gcm_encrypt(key, iv, plaintext, len, ciphertext, tag);
    if (ret != 0) {
        ESP_LOGE(TAG, "FAILURE: AES-GCM encrypt failed (%d)", ret);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "AES-GCM: decrypting...");
    ret = crypto_verify_aes_gcm_decrypt(key, iv, ciphertext, len, tag, decrypted);
    if (ret == 0 && memcmp(plaintext, decrypted, len) == 0) {
        ESP_LOGI(TAG, "SUCCESS: AES-GCM round-trip matched!");
    } else {
        ESP_LOGE(TAG, "FAILURE: AES-GCM round-trip did not match");
    }

    uint8_t bad_tag[CRYPTO_VERIFY_TAG_BYTES];
    memcpy(bad_tag, tag, CRYPTO_VERIFY_TAG_BYTES);
    bad_tag[0] ^= 0xFF;

    ret = crypto_verify_aes_gcm_decrypt(key, iv, ciphertext, len, bad_tag, decrypted);
    if (ret != 0) {
        ESP_LOGI(TAG, "SUCCESS: tampered tag correctly rejected!");
    } else {
        ESP_LOGE(TAG, "FAILURE: tampered tag was accepted (should not happen)");
    }

    vTaskDelete(NULL);
}

static void aes_gcm_demo_task(void *pvParameters)
{
    aes_gcm_text_demo();
    vTaskDelete(NULL);
}

static void mlkem_keypair_task(void *pvParameters)
{
    uint8_t pk[MLKEM_PUBLICKEYBYTES(512)];
    uint8_t sk[MLKEM_SECRETKEYBYTES(512)];
    uint8_t ct[MLKEM_CIPHERTEXTBYTES(512)];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];

    ESP_LOGI(TAG, "Generating ML-KEM-512 keypair...");
    PQCP_MLKEM_NATIVE_MLKEM512_keypair(pk, sk);

    ESP_LOGI(TAG, "Encapsulating...");
    PQCP_MLKEM_NATIVE_MLKEM512_enc(ct, ss_enc, pk);

    ESP_LOGI(TAG, "Decapsulating...");
    int dec_res = PQCP_MLKEM_NATIVE_MLKEM512_dec(ss_dec, ct, sk);
    if (dec_res != 0) {
        ESP_LOGE(TAG, "MLKEM decapsulation error code: %d", dec_res);
    }

    if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0) {
        ESP_LOGI(TAG, "SUCCESS: shared secrets match!");
    } else {
        ESP_LOGE(TAG, "FAILURE: shared secrets do NOT match");
    }

    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "esp32-pq-ota starting up");

    BaseType_t task_result = xTaskCreate(mlkem_keypair_task, "mlkem_keypair", 32768, NULL, 5, NULL);
    if (task_result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create mlkem_keypair_task");
    }

    task_result = xTaskCreate(mldsa_test_task, "mldsa_test", 65536, NULL, 5, NULL);
    if (task_result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create mldsa_test_task");
    }

    task_result = xTaskCreate(aes_gcm_test_task, "aes_gcm_test", 65536, NULL, 5, NULL);
    if (task_result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create aes_gcm_test_task");
    }

    task_result = xTaskCreate(aes_gcm_demo_task, "aes_gcm_demo", 65536, NULL, 5, NULL);
    if (task_result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create aes_gcm_demo_task");
    }
}