# Cryptographic primitive timings

- python: 3.13.7
- platform: Windows-11-10.0.26200-SP0
- processor: Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- generated: 2026-09-22T23:57:55+0800

| label | family | operation | median_ms | mean_ms | ops_per_second | public_key_bytes | ciphertext_bytes | signature_bytes | post_quantum |
|---|---|---|---|---|---|---|---|---|---|
| ecdh-kem-placeholder.keygen | kem | keygen | 0.0296 | 1.4256 | 33783.8 | 32 | 32 |  | False |
| ecdh-kem-placeholder.encaps | kem | encapsulate | 0.0539 | 0.0603 | 18552.9 | 32 | 32 |  | False |
| ecdh-kem-placeholder.decaps | kem | decapsulate | 0.0536 | 0.0563 | 18656.7 | 32 | 32 |  | False |
| hqc-128.keygen | kem | keygen | 0.8177 | 1.0508 | 1223.0 | 2241 | 4433 |  | True |
| hqc-128.encaps | kem | encapsulate | 1.623 | 1.7346 | 616.1 | 2241 | 4433 |  | True |
| hqc-128.decaps | kem | decapsulate | 2.5513 | 2.7115 | 392.0 | 2241 | 4433 |  | True |
| hqc-192.keygen | kem | keygen | 2.5134 | 3.2042 | 397.9 | 4514 | 8978 |  | True |
| hqc-192.encaps | kem | encapsulate | 5.0629 | 5.478 | 197.5 | 4514 | 8978 |  | True |
| hqc-192.decaps | kem | decapsulate | 7.8587 | 8.2735 | 127.2 | 4514 | 8978 |  | True |
| hqc-256.keygen | kem | keygen | 4.8613 | 6.1477 | 205.7 | 7237 | 14421 |  | True |
| hqc-256.encaps | kem | encapsulate | 9.5602 | 10.0658 | 104.6 | 7237 | 14421 |  | True |
| hqc-256.decaps | kem | decapsulate | 14.505 | 15.1338 | 68.9 | 7237 | 14421 |  | True |
| ml-kem-1024.keygen | kem | keygen | 0.0659 | 0.0927 | 15174.5 | 1568 | 1568 |  | True |
| ml-kem-1024.encaps | kem | encapsulate | 0.0743 | 0.0845 | 13459.0 | 1568 | 1568 |  | True |
| ml-kem-1024.decaps | kem | decapsulate | 0.0962 | 0.108 | 10395.0 | 1568 | 1568 |  | True |
| ml-kem-512.keygen | kem | keygen | 0.0246 | 0.0369 | 40650.4 | 800 | 768 |  | True |
| ml-kem-512.encaps | kem | encapsulate | 0.0292 | 0.0317 | 34246.6 | 800 | 768 |  | True |
| ml-kem-512.decaps | kem | decapsulate | 0.0401 | 0.042 | 24937.7 | 800 | 768 |  | True |
| ml-kem-768.keygen | kem | keygen | 0.0408 | 0.0529 | 24509.8 | 1184 | 1088 |  | True |
| ml-kem-768.encaps | kem | encapsulate | 0.0497 | 0.0537 | 20120.7 | 1184 | 1088 |  | True |
| ml-kem-768.decaps | kem | decapsulate | 0.0606 | 0.0655 | 16501.7 | 1184 | 1088 |  | True |
| ecdsa-p256-sha256.keygen | classical | keygen | 0.0205 | 0.0721 | 48780.5 | 65 |  | 72 | False |
| ecdsa-p256-sha256.sign | classical | sign | 0.0191 | 0.033 | 52355.9 | 65 |  | 70 | False |
| ecdsa-p256-sha256.verify | classical | verify | 0.0621 | 0.0687 | 16103.1 | 65 |  | 70 | False |
| ed25519.keygen | classical | keygen | 0.0276 | 0.0446 | 36166.4 | 32 |  | 64 | False |
| ed25519.sign | classical | sign | 0.0243 | 0.0261 | 41152.2 | 32 |  | 64 | False |
| ed25519.verify | classical | verify | 0.0727 | 0.0803 | 13755.2 | 32 |  | 64 | False |
| falcon-1024.keygen | post-quantum | keygen | 26.5052 | 32.1957 | 37.7 | 1793 |  | 1462 | True |
| falcon-1024.sign | post-quantum | sign | 6.6139 | 6.9522 | 151.2 | 1793 |  | 1273 | True |
| falcon-1024.verify | post-quantum | verify | 0.0608 | 0.0639 | 16447.4 | 1793 |  | 1273 | True |
| falcon-512.keygen | post-quantum | keygen | 9.357 | 14.0599 | 106.9 | 897 |  | 752 | True |
| falcon-512.sign | post-quantum | sign | 3.1821 | 3.3812 | 314.3 | 897 |  | 652 | True |
| falcon-512.verify | post-quantum | verify | 0.0304 | 0.0321 | 32894.7 | 897 |  | 652 | True |
| falcon-padded-1024.keygen | post-quantum | keygen | 22.7803 | 35.2832 | 43.9 | 1793 |  | 1280 | True |
| falcon-padded-1024.sign | post-quantum | sign | 6.6102 | 6.9737 | 151.3 | 1793 |  | 1280 | True |
| falcon-padded-1024.verify | post-quantum | verify | 0.0613 | 0.0724 | 16313.2 | 1793 |  | 1280 | True |
| falcon-padded-512.keygen | post-quantum | keygen | 8.6635 | 11.0946 | 115.4 | 897 |  | 666 | True |
| falcon-padded-512.sign | post-quantum | sign | 3.0656 | 3.2547 | 326.2 | 897 |  | 666 | True |
| falcon-padded-512.verify | post-quantum | verify | 0.0305 | 0.0348 | 32786.9 | 897 |  | 666 | True |
| ml-dsa-44.keygen | post-quantum | keygen | 0.0867 | 0.1154 | 11527.4 | 1312 |  | 2420 | True |
| ml-dsa-44.sign | post-quantum | sign | 4.1991 | 4.4023 | 238.1 | 1312 |  | 2420 | True |
| ml-dsa-44.verify | post-quantum | verify | 0.0763 | 0.0802 | 13106.2 | 1312 |  | 2420 | True |
| ml-dsa-65.keygen | post-quantum | keygen | 0.1499 | 0.1923 | 6673.3 | 1952 |  | 3309 | True |
| ml-dsa-65.sign | post-quantum | sign | 5.8662 | 6.2001 | 170.5 | 1952 |  | 3309 | True |
| ml-dsa-65.verify | post-quantum | verify | 0.1184 | 0.1338 | 8445.9 | 1952 |  | 3309 | True |
| ml-dsa-87.keygen | post-quantum | keygen | 0.213 | 0.2745 | 4694.8 | 2592 |  | 4627 | True |
| ml-dsa-87.sign | post-quantum | sign | 7.9212 | 8.4849 | 126.2 | 2592 |  | 4627 | True |
| ml-dsa-87.verify | post-quantum | verify | 0.1844 | 0.1946 | 5423.0 | 2592 |  | 4627 | True |
| xmss.keygen | post-quantum | keygen | 740.7407 | 740.7416 | 1.3 | 64 |  | 4548 | True |
| xmss.sign | post-quantum | sign | 4.1336 | 4.2945 | 241.9 | 64 |  | 4548 | True |
| xmss.verify | post-quantum | verify | 1.2428 | 1.3955 | 804.6 | 64 |  | 4548 | True |
