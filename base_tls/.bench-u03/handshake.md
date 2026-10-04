# Hybrid handshake size and latency

- python: 3.12.10
- platform: Windows-11-10.0.26200-SP0
- processor: AMD64 Family 25 Model 117 Stepping 2, AuthenticAMD
- generated: 2026-09-21T23:56:01+0800

| kem | pq_signer | handshake_bytes | client_bytes | server_bytes | pq_delta_bytes | handshake_ms | bytes.ClientHello | bytes.ServerHello | bytes.Certificate | bytes.CertificateVerify | stage_ms.server_kem_encaps | stage_ms.client_kem_decaps | stage_ms.server_sign_pq | stage_ms.client_verify_pq | ok |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ml-kem-768 | falcon-512 | 1404 | 169 | 1235 | 0 | 1.262 | 112 | 91 | 959 | 100 | 0.0 | 0.0 | 0.0 | 0.0 | True |
| ml-kem-768 | falcon-512 | 5271 | 1363 | 3908 | 3848 | 11.117 | 1306 | 1185 | 1882 | 757 | 0.075 | 0.08 | 8.154 | 0.064 | True |
| ml-kem-768 | xmss | 8391 | 1363 | 7028 | 6972 | 7.08 | 1306 | 1185 | 1042 | 4716 | 0.074 | 0.086 | 4.163 | 1.059 | True |
