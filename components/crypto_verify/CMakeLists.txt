idf_component_register(
    SRCS
        "src/crypto_verify.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES
        mbedtls
)