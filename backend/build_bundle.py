#!/usr/bin/env python3
"""
build_bundle.py — PQC OTA bundle builder (backend/server side)

Takes the device's ML-KEM-512 public key (the hex string printed by
pqc_keys_init() on the ESP32) and the vendor's ML-DSA-44 secret key
(vendor_dsa_sk.bin, produced by gen_vendor_keys.py), encrypts + signs a
firmware file, and writes bundle.bin in the exact wire format that
ota_http_download.c expects:

    [ ct_kem   : 768 bytes  ]  ML-KEM-512 ciphertext
    [ sig      : 2420 bytes ]  ML-DSA-44 signature over SHA-256(plaintext)
    [ tag      : 16 bytes   ]  AES-GCM auth tag
    [ length   : 4 bytes LE ]  ciphertext length
    [ ciphertext : length bytes ]

Usage:
    python build_bundle.py \
        --kem-pk-hex "aabbcc..."          # or a path to a file containing it
        --vendor-sk vendor_dsa_sk.bin \
        --firmware path/to/firmware.bin \
        --out bundle.bin

Then serve it with server.py and point the ESP32's FIRMWARE_URL at
http://<this-machine-LAN-IP>:8080/firmware after uploading via /upload.
"""

import argparse
import hashlib
import os
import struct
import sys

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Must match the string in aes_gcm_demo.c / ota_task.c exactly.
HKDF_INFO = b"esp32-pq-ota-aes-key-v1"

# Matches the fixed demo IV used on the device side (memset(iv, 0x13, ...)).
# NOTE: a fixed IV is fine for a same-key, single-use demo bundle, but is not
# safe to reuse across multiple bundles encrypted under the same AES key.
# For anything beyond this bring-up test, generate a fresh random IV per
# bundle and transmit it in the header instead of hardcoding it on both ends.
DEMO_IV = b"\x13" * 12


def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO)
    return hkdf.derive(shared_secret)


def load_kem_pk(arg: str) -> bytes:
    """Accept either a raw hex string or a path to a file containing one."""
    if os.path.exists(arg):
        # utf-8-sig silently drops the BOM that Notepad sometimes adds
        with open(arg, "r", encoding="utf-8-sig") as f:
            arg = f.read()
    elif not all(c in "0123456789abcdefABCDEF=_ \n\r\tKEMPXDVI" for c in arg) or len(arg) < 200:
        sys.exit(f"ERROR: '{arg[:40]}' is not a file that exists in {os.getcwd()} "
                 f"and doesn't look like a hex key. Check the filename "
                 f"(Notepad may have saved it as kem_pk.hex.txt).")
    # Tolerate pasting the whole serial line: "DEVICE_KEM_PK_HEX=<hex>"
    arg = arg.split("=")[-1]
    arg = "".join(arg.split())  # drop any spaces/newlines inside the key
    try:
        return bytes.fromhex(arg)
    except ValueError:
        sys.exit("ERROR: the key contains non-hex characters. It should be "
                 "exactly 1600 characters of 0-9 and a-f.")


def main():
    ap = argparse.ArgumentParser(description="Build a signed + encrypted PQC OTA bundle")
    ap.add_argument("--kem-pk-hex", required=True,
                     help="Device ML-KEM-512 public key: hex string, or path to a file containing it")
    ap.add_argument("--vendor-sk", required=True,
                     help="Path to vendor_dsa_sk.bin (from gen_vendor_keys.py)")
    ap.add_argument("--firmware", required=True,
                     help="Path to the firmware/payload file to encrypt")
    ap.add_argument("--out", default="bundle.bin",
                     help="Output bundle path (default: bundle.bin)")
    args = ap.parse_args()

    kem_pk = load_kem_pk(args.kem_pk_hex)
    if len(kem_pk) != 800:
        sys.exit(f"ERROR: expected an 800-byte ML-KEM-512 public key, got {len(kem_pk)} bytes")

    with open(args.vendor_sk, "rb") as f:
        vendor_sk = f.read()

    with open(args.firmware, "rb") as f:
        plaintext = f.read()

    print(f"Firmware:        {args.firmware} ({len(plaintext)} bytes)")

    # --- ML-KEM-512 encapsulation against the device's real public key ---
    with oqs.KeyEncapsulation("ML-KEM-512") as kem:
        ct_kem, shared_secret = kem.encap_secret(kem_pk)
    print(f"ML-KEM ciphertext: {len(ct_kem)} bytes (expect 768)")

    # --- HKDF-SHA256 -> AES-256 key, same info string as the device ---
    aes_key = derive_aes_key(shared_secret)

    # --- AES-256-GCM encrypt the firmware ---
    aesgcm = AESGCM(aes_key)
    ct_and_tag = aesgcm.encrypt(DEMO_IV, plaintext, None)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    print(f"Ciphertext:      {len(ciphertext)} bytes, tag: {len(tag)} bytes")

    # --- Hash the plaintext and sign with the vendor's ML-DSA-44 secret key ---
    plaintext_hash = hashlib.sha256(plaintext).digest()
    with oqs.Signature("ML-DSA-44", secret_key=vendor_sk) as signer:
        sig = signer.sign(plaintext_hash)
    print(f"ML-DSA signature: {len(sig)} bytes (expect 2420)")

    # --- Assemble bundle exactly as ota_http_download.c reads it ---
    length_field = struct.pack("<I", len(ciphertext))
    bundle = ct_kem + sig + tag + length_field + ciphertext

    with open(args.out, "wb") as f:
        f.write(bundle)

    print(f"\nWrote {args.out}: {len(bundle)} bytes total")
    print(f"  ct_kem={len(ct_kem)}  sig={len(sig)}  tag={len(tag)}  "
          f"len_field=4  ciphertext={len(ciphertext)}")


if __name__ == "__main__":
    main()