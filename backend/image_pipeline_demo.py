"""
esp32-pq-ota — Full pipeline demo (PC-only simulation)
Encrypts an image using ML-KEM-512 + HKDF-SHA256 + AES-256-GCM,
signs it with ML-DSA-44, then reverses the whole process and
verifies the output matches the original — printing every stage.
"""

import sys
import hashlib
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"esp32-pq-ota-aes-key-v1"  # must match device-side string exactly


def hexify(b, n=32):
    """Show first n bytes of a buffer as hex, for readable printing."""
    return b[:n].hex() + ("..." if len(b) > n else "")


def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # AES-256 key
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def main():
    if len(sys.argv) != 2:
        print("Usage: python image_pipeline_demo.py <path-to-image>")
        sys.exit(1)

    image_path = sys.argv[1]

    print("=" * 70)
    print("STAGE 0 — Load input file")
    print("=" * 70)
    with open(image_path, "rb") as f:
        plaintext = f.read()
    print(f"File: {image_path}")
    print(f"Size: {len(plaintext)} bytes")
    print(f"First bytes (hex): {hexify(plaintext)}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 1 — ML-KEM-512 keypair (simulating the ESP32 device)")
    print("=" * 70)
    kem = oqs.KeyEncapsulation("ML-KEM-512")
    kem_public_key = kem.generate_keypair()
    print(f"Public key length: {len(kem_public_key)} bytes (expect 800)")
    print(f"Public key (hex):  {hexify(kem_public_key)}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 2 — ML-KEM-512 encapsulation (backend side)")
    print("=" * 70)
    kem_ciphertext, shared_secret = kem.encap_secret(kem_public_key)
    print(f"KEM ciphertext length: {len(kem_ciphertext)} bytes (expect 768)")
    print(f"KEM ciphertext (hex):  {hexify(kem_ciphertext)}")
    print(f"Shared secret (hex):   {hexify(shared_secret)}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 3 — HKDF-SHA256 key derivation")
    print("=" * 70)
    aes_key = derive_aes_key(shared_secret)
    print(f"Derived AES-256 key (hex): {hexify(aes_key)}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 4 — AES-256-GCM encryption of the image")
    print("=" * 70)
    aesgcm = AESGCM(aes_key)
    iv = b"\x13" * 12  # fixed IV for demo only — real backend must use a fresh random IV per bundle
    ct_and_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    print(f"IV (hex):         {iv.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Ciphertext (hex):  {hexify(ciphertext)}")
    print(f"Auth tag (hex):    {tag.hex()}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 5 — SHA-256 hash of plaintext + ML-DSA-44 signing")
    print("=" * 70)
    plaintext_hash = hashlib.sha256(plaintext).digest()
    print(f"Plaintext SHA-256 (hex): {plaintext_hash.hex()}")

    sig = oqs.Signature("ML-DSA-44")
    dsa_public_key = sig.generate_keypair()
    signature = sig.sign(plaintext_hash)
    print(f"ML-DSA public key length: {len(dsa_public_key)} bytes (expect 1312)")
    print(f"Signature length: {len(signature)} bytes (expect 2420)")
    print(f"Signature (hex):  {hexify(signature)}\n")

    print("### BUNDLE ASSEMBLED — this is what would be sent to the device ###\n")

    # =============================================================
    # DEVICE-SIDE SIMULATION (decrypt-then-verify)
    # =============================================================
    print("=" * 70)
    print("STAGE 6 — [DEVICE] ML-KEM-512 decapsulation")
    print("=" * 70)
    dec_shared_secret = kem.decap_secret(kem_ciphertext)
    print(f"Decapsulated shared secret (hex): {hexify(dec_shared_secret)}")
    print(f"Matches original shared secret: {dec_shared_secret == shared_secret}\n")

    print("=" * 70)
    print("STAGE 7 — [DEVICE] HKDF re-derive AES key")
    print("=" * 70)
    dec_aes_key = derive_aes_key(dec_shared_secret)
    print(f"Re-derived AES-256 key (hex): {hexify(dec_aes_key)}")
    print(f"Matches original derived key: {dec_aes_key == aes_key}\n")

    print("=" * 70)
    print("STAGE 8 — [DEVICE] AES-256-GCM decrypt (auth tag checked here)")
    print("=" * 70)
    dec_aesgcm = AESGCM(dec_aes_key)
    try:
        decrypted = dec_aesgcm.decrypt(iv, ciphertext + tag, None)
        print("AES-GCM decrypt + tag verification: SUCCESS")
        print(f"Decrypted size: {len(decrypted)} bytes\n")
    except Exception as e:
        print(f"AES-GCM decrypt FAILED: {e}")
        sys.exit(1)

    print("=" * 70)
    print("STAGE 9 — [DEVICE] Hash decrypted plaintext + verify ML-DSA signature")
    print("=" * 70)
    dec_hash = hashlib.sha256(decrypted).digest()
    print(f"Decrypted plaintext SHA-256 (hex): {dec_hash.hex()}")
    try:
        sig_valid = sig.verify(dec_hash, signature, dsa_public_key)
    except Exception:
        sig_valid = False
    print(f"ML-DSA-44 signature verified: {sig_valid}\n")

    # -----------------------------------------------------------
    print("=" * 70)
    print("STAGE 10 — Final check + save output")
    print("=" * 70)
    match = (decrypted == plaintext)
    print(f"Decrypted output matches original file byte-for-byte: {match}")

    if match and sig_valid:
        out_path = image_path + ".decrypted" + image_path[image_path.rfind("."):]
        with open(out_path, "wb") as f:
            f.write(decrypted)
        print(f"\nSUCCESS: Full pipeline passed. Decrypted image saved to: {out_path}")
    else:
        print("\nFAILURE: Pipeline did not complete correctly.")


if __name__ == "__main__":
    main()