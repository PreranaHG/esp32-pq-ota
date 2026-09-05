#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"
#include "bootloader_random.h"

int randombytes(uint8_t *out, size_t outlen)
{
    bootloader_random_enable();
    esp_fill_random(out, outlen);
    bootloader_random_disable();
    return 0;
}