# Loopback TCP handshake: round trips and transport overhead

- python: 3.13.7
- platform: Windows-11-10.0.26200-SP0
- processor: Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- generated: 2026-09-22T23:58:41+0800

| kem | pq_signer | handshake_bytes | waits_to_authenticated | one_rtt | tcp_median_ms | in_process_median_ms | transport_overhead_ms | ok |
|---|---|---|---|---|---|---|---|---|
| ml-kem-768 | falcon-512 | 4470 | [1] | True | 8.872 | 4.779 | 4.093 | True |
| ml-kem-768 | ml-dsa-44 | 6650 | [1] | True | 16.216 | 5.735 | 10.481 | True |
| ml-kem-768 | xmss | 7529 | [1] | True | 17.199 | 5.989 | 11.211 | True |
