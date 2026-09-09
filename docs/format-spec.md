\# esp32-pq-ota Bundle Format Spec

\## Byte layout (backend writes, device parses)

\[4 bytes] length of ML-KEM-512 ciphertext (always 768, included for robustness)

\[768 bytes] ML-KEM-512 ciphertext

\[4 bytes] length of ML-DSA-44 signature (always 2420)

\[2420 bytes] ML-DSA-44 signature

\[4 bytes] length of AES-GCM tag (always 16)

\[16 bytes] AES-GCM authentication tag

\[4 bytes] length of AES-GCM ciphertext (variable, depends on firmware size)

\[N bytes] AES-GCM ciphertext (the encrypted firmware itself)

\## Notes

## Notes

- ML-DSA-44 signature covers SHA-256 hash of the PLAINTEXT firmware (pre-encryption) — signed once at release time, valid across all re-encrypted distributions of the same firmware
- AES-256 key is derived from the ML-KEM shared secret via HKDF-SHA256:
  - IKM: ML-KEM-512 shared secret (32 bytes)
  - Salt: none (all-zero, per HKDF spec default)
  - Info: "esp32-pq-ota-aes-key-v1" (ASCII, for domain separation; bump version suffix if derivation ever changes)
  - Output: 32 bytes (AES-256 key)
- All multi-byte length fields are little-endian uint32
- Device verification order is DECRYPT-THEN-VERIFY:
  1. AES-GCM decrypt (auth tag check happens here — rejects tampered ciphertext before any plaintext is exposed)
  2. SHA-256 hash the resulting plaintext
  3. ML-DSA-44 verify the signature against that hash
  4. Only if both steps succeed, treat firmware as authentic
- AES-GCM IV/nonce: MUST be unique per encryption (never reused with the same key) — backend generates a fresh random 12-byte IV per bundle and includes it in transit (NOT hardcoded)
