#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mlkem_native.h"
#include "mldsa_native.h"

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

    /* Tamper test: corrupt one byte, confirm verification now fails */
    sig[0] ^= 0xFF;
    int tampered = mldsa44_verify(sig, msg, msglen, NULL, 0, pk);
    if (tampered != 0) {
        ESP_LOGI(TAG, "SUCCESS: tampered signature correctly rejected!");
    } else {
        ESP_LOGE(TAG, "FAILURE: tampered signature was accepted (should not happen)");
    }

    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "esp32-pq-ota starting up");

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
    PQCP_MLKEM_NATIVE_MLKEM512_dec(ss_dec, ct, sk);

    if (memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0) {
        ESP_LOGI(TAG, "SUCCESS: shared secrets match!");
    } else {
        ESP_LOGE(TAG, "FAILURE: shared secrets do NOT match");
    }

    /* ML-DSA-44 needs a much larger stack (~50KB+ for signing) than
     * app_main's — run it in its own dedicated task rather than
     * growing app_main's stack unnecessarily. */
    BaseType_t task_result = xTaskCreate(mldsa_test_task, "mldsa_test", 65536, NULL, 5, NULL);
    if (task_result != pdPASS) {
        ESP_LOGE(TAG, "FAILED to create mldsa_test_task — likely insufficient heap for stack allocation");
    }
}