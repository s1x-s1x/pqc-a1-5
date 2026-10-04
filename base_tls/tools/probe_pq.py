"""Enumerate the pqcrypto submodules that actually import in this environment."""

from __future__ import annotations

import importlib

KEM_CANDIDATES = [
    "ml_kem_512", "ml_kem_768", "ml_kem_1024",
    "kyber512", "kyber768", "kyber1024",
    "hqc_128", "hqc_192", "hqc_256",
    "mceliece348864", "mceliece460896", "mceliece6688128", "mceliece6960119",
    "sntrup761", "ntru_hps2048509", "ntru_hps4096821", "ntru_hrss701",
    "bike1l1cpa", "classic_mceliece_348864",
]

SIGN_CANDIDATES = [
    "ml_dsa_44", "ml_dsa_65", "ml_dsa_87",
    "dilithium2", "dilithium3", "dilithium5",
    "falcon_512", "falcon_1024", "falcon_padded_512", "falcon_padded_1024",
    "sphincs_sha2_128f_simple", "sphincs_sha2_128s_simple",
    "sphincsplus_sha2_128f_simple", "sphincs_sha2_128f_robust",
    "sphincs_shake_128f_simple", "mayo_1", "cross_rsdp_128f_fast",
]

print("=== KEM ===")
for name in KEM_CANDIDATES:
    try:
        module = importlib.import_module(f"pqcrypto.kem.{name}")
    except Exception as error:  # noqa: BLE001 - enumeration reports every failure
        continue
    attrs = [a for a in ("keygen", "encaps", "decaps", "encrypt", "decrypt") if hasattr(module, a)]
    sizes = {
        a: getattr(module, a)
        for a in ("PUBLIC_KEY_SIZE", "SECRET_KEY_SIZE", "CIPHERTEXT_SIZE", "SHARED_SECRET_SIZE")
        if hasattr(module, a)
    }
    print(f"  {name:26s} {attrs} {sizes}")

print("=== SIGN ===")
for name in SIGN_CANDIDATES:
    try:
        module = importlib.import_module(f"pqcrypto.sign.{name}")
    except Exception as error:  # noqa: BLE001 - enumeration reports every failure
        continue
    attrs = [a for a in ("keygen", "sign", "verify") if hasattr(module, a)]
    sizes = {
        a: getattr(module, a)
        for a in ("PUBLIC_KEY_SIZE", "SECRET_KEY_SIZE", "SIGNATURE_SIZE", "SIG_SIZE")
        if hasattr(module, a)
    }
    print(f"  {name:26s} {attrs} {sizes}")
