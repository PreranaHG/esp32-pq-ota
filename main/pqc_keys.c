#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mlkem_native.h"
#include "mldsa_native.h"
#include "pqc_keys.h"
#include "vendor_dsa_pk.h"   // provides VENDOR_DSA_PK[MLDSA44_PUBLICKEYBYTES]

static const char *TAG = "pqc_keys";

#define NVS_NAMESPACE "pqc"
#define NVS_KEY_KEM_PK "kem_pk"
#define NVS_KEY_KEM_SK "kem_sk"

#define KEM_PK_LEN MLKEM_PUBLICKEYBYTES(512)
#define KEM_SK_LEN MLKEM_SECRETKEYBYTES(512)

static uint8_t *s_kem_pk = NULL;
static uint8_t *s_kem_sk = NULL;

static void print_kem_pk_hex(void)
{
    // Copy this line from the serial monitor into your backend (device_kem_pk.hex)
    printf("DEVICE_KEM_PK_HEX=");
    for (size_t i = 0; i < KEM_PK_LEN; i++) {
        printf("%02x", s_kem_pk[i]);
    }
    printf("\n");
}

static int load_from_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return -1;
    }

    size_t pk_len = KEM_PK_LEN, sk_len = KEM_SK_LEN;
    esp_err_t e1 = nvs_get_blob(h, NVS_KEY_KEM_PK, s_kem_pk, &pk_len);
    esp_err_t e2 = nvs_get_blob(h, NVS_KEY_KEM_SK, s_kem_sk, &sk_len);
    nvs_close(h);

    if (e1 == ESP_OK && e2 == ESP_OK && pk_len == KEM_PK_LEN && sk_len == KEM_SK_LEN) {
        return 0;
    }
    return -1;
}

static int save_to_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }

    esp_err_t e1 = nvs_set_blob(h, NVS_KEY_KEM_PK, s_kem_pk, KEM_PK_LEN);
    esp_err_t e2 = nvs_set_blob(h, NVS_KEY_KEM_SK, s_kem_sk, KEM_SK_LEN);
    esp_err_t e3 = nvs_commit(h);
    nvs_close(h);

    return (e1 == ESP_OK && e2 == ESP_OK && e3 == ESP_OK) ? 0 : -1;
}

void pqc_keys_init(void)
{
    // NVS init is safe to call more than once (wifi_init_sta also calls it)
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    // Key buffers live on the heap, not the stack
    s_kem_pk = malloc(KEM_PK_LEN);
    s_kem_sk = malloc(KEM_SK_LEN);
    if (!s_kem_pk || !s_kem_sk) {
        ESP_LOGE(TAG, "Heap allocation failed for ML-KEM keys");
        abort();
    }

    if (load_from_nvs() == 0) {
        ESP_LOGI(TAG, "ML-KEM-512 keypair loaded from NVS");
    } else {
        ESP_LOGI(TAG, "No stored ML-KEM keypair, generating a new one...");
        PQCP_MLKEM_NATIVE_MLKEM512_keypair(s_kem_pk, s_kem_sk);
        if (save_to_nvs() != 0) {
            ESP_LOGE(TAG, "Failed to store keypair in NVS (will regenerate next boot!)");
        } else {
            ESP_LOGI(TAG, "ML-KEM-512 keypair stored in NVS");
        }
    }

    print_kem_pk_hex();

    // Warn if the vendor public key is still the all-zero placeholder
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(VENDOR_DSA_PK); i++) {
        if (VENDOR_DSA_PK[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) {
        ESP_LOGW(TAG, "vendor_dsa_pk.h is a placeholder - run gen_vendor_keys.py and rebuild!");
    }
}

const uint8_t *pqc_get_kem_sk(void) { return s_kem_sk; }
const uint8_t *pqc_get_kem_pk(void) { return s_kem_pk; }
const uint8_t *pqc_get_dsa_pk(void) { return VENDOR_DSA_PK; }