idf_component_register(SRCS "pqc_keys.c" "ota_task.c" "pqc_ota_main.c" "aes_gcm_demo.c" "wifi_init.c" "ota_http_download.c"
                    INCLUDE_DIRS "."
                    REQUIRES mlkem512 mldsa44 crypto_verify esp_http_client esp_wifi esp_netif esp_event nvs_flash app_update esp_timer
                    PRIV_REQUIRES mbedtls)