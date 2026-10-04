# Cryptographic primitive timings

- python: 3.12.10
- platform: Windows-11-10.0.26200-SP0
- processor: AMD64 Family 25 Model 117 Stepping 2, AuthenticAMD
- generated: 2026-09-21T23:55:22+0800

| label | family | operation | median_ms | mean_ms | ops_per_second | public_key_bytes | ciphertext_bytes | signature_bytes | post_quantum |
|---|---|---|---|---|---|---|---|---|---|
| ml-kem-768.keygen | kem | keygen | 0.0855 | 0.087 | 11695.9 | 1184 | 1088 |  | True |
| ml-kem-768.encaps | kem | encapsulate | 0.0511 | 0.06 | 19569.5 | 1184 | 1088 |  | True |
| ml-kem-768.decaps | kem | decapsulate | 0.0661 | 0.0749 | 15128.6 | 1184 | 1088 |  | True |
| xmss.keygen | post-quantum | keygen | 2282.1731 | 2282.1745 | 0.4 | 64 |  | 4612 | True |
| xmss.sign | post-quantum | sign | 3.0819 | 3.5636 | 324.5 | 64 |  | 4612 | True |
| xmss.verify | post-quantum | verify | 1.2133 | 1.3681 | 824.2 | 64 |  | 4612 | True |
