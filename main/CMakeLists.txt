idf_component_register(SRCS "pqc_ota_main.c" "aes_gcm_demo.c"
                    INCLUDE_DIRS "."
                    REQUIRES mlkem512 mldsa44 crypto_verify
                    PRIV_REQUIRES mbedtls)

