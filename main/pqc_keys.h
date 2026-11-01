#ifndef PQC_KEYS_H
#define PQC_KEYS_H

#include <stdint.h>

/**
 * Call once from app_main() before starting the OTA task.
 *
 * - ML-KEM-512 keypair (device's own): loaded from NVS, or generated and
 *   stored on the first boot. The public key is printed to the serial
 *   monitor so the backend can encapsulate to it.
 * - ML-DSA-44 public key (vendor's): compiled into the firmware from
 *   vendor_dsa_pk.h. The device only verifies, it never signs.
 *
 * NOTE: needs ~16KB main task stack (menuconfig -> Main task stack size).
 */
void pqc_keys_init(void);

const uint8_t *pqc_get_kem_sk(void);   // device ML-KEM-512 secret key
const uint8_t *pqc_get_kem_pk(void);   // device ML-KEM-512 public key
const uint8_t *pqc_get_dsa_pk(void);   // vendor ML-DSA-44 public key

#endif // PQC_KEYS_H