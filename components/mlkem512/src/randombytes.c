#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"

int randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
    return 0;
}