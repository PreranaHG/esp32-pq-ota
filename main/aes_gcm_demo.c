#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mlkem_native.h"
#include "mldsa_native.h"
#include "crypto_verify.h"
#include "aes_gcm_demo.h"

static const char *TAG = "pqc_hybrid";

// Custom helper function to read a full sentence until newline
static void read_full_line(char *buf, size_t max_len)
{
    size_t idx = 0;
    while (idx < max_len - 1) {
        int c = getchar();
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        // Handle Enter key press (\n or \r)
        if (c == '\n' || c == '\r') {
            if (idx > 0) break; // Finished reading valid sentence input
            continue;           // Ignore leading empty newlines
        }

        // Echo typed character to monitor so you can see what you type
        putchar(c);
        fflush(stdout);

        buf[idx++] = (char)c;
    }
    buf[idx] = '\0';
    printf("\n"); // New line after pressing Enter
}

void aes_gcm_text_demo(void)
{
    // Allocate large PQC key buffers on the Heap to prevent Stack Overflow crashes
    uint8_t *dsa_pk = pvPortMalloc(MLDSA44_PUBLICKEYBYTES);
    uint8_t *dsa_sk = pvPortMalloc(MLDSA44_SECRETKEYBYTES);
    uint8_t *kem_pk = pvPortMalloc(MLKEM_PUBLICKEYBYTES(512));
    uint8_t *kem_sk = pvPortMalloc(MLKEM_SECRETKEYBYTES(512));

    if (!dsa_pk || !dsa_sk || !kem_pk || !kem_sk) {
        ESP_LOGE(TAG, "Heap allocation failed for PQC keypairs!");
        if (dsa_pk) vPortFree(dsa_pk);
        if (dsa_sk) vPortFree(dsa_sk);
        if (kem_pk) vPortFree(kem_pk);
        if (kem_sk) vPortFree(kem_sk);
        return;
    }

    ESP_LOGI(TAG, "Generating ML-DSA-44 Keypair on heap...");
    mldsa44_keypair(dsa_pk, dsa_sk);

    ESP_LOGI(TAG, "Generating ML-KEM-512 Keypair on heap...");
    PQCP_MLKEM_NATIVE_MLKEM512_keypair(kem_pk, kem_sk);

    char input_buf[256];

    while (1) {
        printf("\n=======================================================\n");
        printf("Enter message to process with ML-KEM + AES-GCM + ML-DSA:\n> ");
        fflush(stdout);

        read_full_line(input_buf, sizeof(input_buf));

        if (strlen(input_buf) == 0) continue;
        if (strcmp(input_buf, "exit") == 0) {
            ESP_LOGI(TAG, "Exiting PQC Demo.");
            break;
        }

        size_t len = strlen(input_buf);
        ESP_LOGI(TAG, "Input Plaintext : \"%s\" (%zu bytes)", input_buf, len);

        // --- STEP A: ML-KEM Key Exchange ---
        uint8_t ct_kem[MLKEM_CIPHERTEXTBYTES(512)];
        uint8_t aes_key[MLKEM_BYTES]; 
        PQCP_MLKEM_NATIVE_MLKEM512_enc(ct_kem, aes_key, kem_pk);
        ESP_LOGI(TAG, "[ML-KEM-512] Encapsulated symmetric key generated");

        // --- STEP B: AES-GCM Encryption ---
        uint8_t iv[CRYPTO_VERIFY_IV_BYTES];
        memset(iv, 0x13, sizeof(iv)); // Demo IV
        uint8_t ciphertext[256];
        uint8_t tag[CRYPTO_VERIFY_TAG_BYTES];

        int ret = crypto_verify_aes_gcm_encrypt(aes_key, iv, (const uint8_t *)input_buf, len, ciphertext, tag);
        if (ret != 0) {
            ESP_LOGE(TAG, "[AES-GCM] Encryption failed!");
            continue;
        }

        // Display Ciphertext in HEX format
        printf("I (%lu) %s: [AES-GCM] Ciphertext (HEX): ", (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS), TAG);
        for (size_t i = 0; i < len; i++) {
            printf("%02x", ciphertext[i]);
        }
        printf("\n");

        // Display Auth Tag in HEX format
        printf("I (%lu) %s: [AES-GCM] Auth Tag   (HEX): ", (unsigned long)(xTaskGetTickCount() * portTICK_PERIOD_MS), TAG);
        for (int i = 0; i < CRYPTO_VERIFY_TAG_BYTES; i++) {
            printf("%02x", tag[i]);
        }
        printf("\n");

        // --- STEP C: ML-DSA Digital Signature ---
        uint8_t sig[MLDSA44_BYTES];
        mldsa44_signature(sig, ciphertext, len, NULL, 0, dsa_sk);
        ESP_LOGI(TAG, "[ML-DSA-44] Digital signature generated for ciphertext");

        // --- VERIFICATION & DECRYPTION FLOW ---
        // 1. Verify Digital Signature
        int sig_ok = mldsa44_verify(sig, ciphertext, len, NULL, 0, dsa_pk);
        if (sig_ok == 0) {
            ESP_LOGI(TAG, "[ML-DSA-44] Signature VERIFIED!");
        } else {
            ESP_LOGE(TAG, "[ML-DSA-44] Signature Verification FAILED!");
            continue;
        }

        // 2. Decapsulate KEM Shared Secret Key
        uint8_t dec_aes_key[MLKEM_BYTES];
        PQCP_MLKEM_NATIVE_MLKEM512_dec(dec_aes_key, ct_kem, kem_sk);

        // 3. Decrypt AES-GCM Ciphertext
        uint8_t decrypted[256];
        memset(decrypted, 0, sizeof(decrypted));
        ret = crypto_verify_aes_gcm_decrypt(dec_aes_key, iv, ciphertext, len, tag, decrypted);
        decrypted[len] = '\0';

        if (ret == 0 && memcmp(input_buf, decrypted, len) == 0) {
            ESP_LOGI(TAG, "[AES-GCM] Decrypted Output : \"%s\"", decrypted);
            ESP_LOGI(TAG, "SUCCESS: Complete PQC (KEM + AES + DSA) Pipeline Passed!");
        } else {
            ESP_LOGE(TAG, "FAILURE: AES-GCM Decryption or Tag verification failed!");
        }
    }

    // Free allocated memory if loop exits
    vPortFree(dsa_pk);
    vPortFree(dsa_sk);
    vPortFree(kem_pk);
    vPortFree(kem_sk);
}