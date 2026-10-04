# Handshake latency under emulated links

- python: 3.13.7
- platform: Windows-11-10.0.26200-SP0
- processor: Intel64 Family 6 Model 170 Stepping 4, GenuineIntel
- generated: 2026-09-22T23:58:48+0800

| link | rtt_ms | bandwidth_mbps | variant | handshake_bytes | authenticated_ms | authenticated_min_ms | predicted_ms | pq_cost_ms | pq_cost_min_ms | pq_cost_max_ms | pq_cost_predicted_ms | one_rtt | ok |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wan-slow | 195.6 | 10.0 | hybrid | 5262 | 214.424 | 208.233 | 199.783 | 4.57 | -1.59 | 10.73 | 3.099 | True | True |
| wan-slow | 195.6 | 10.0 | classical | 1388 | 209.854 | 209.823 | 196.684 | 4.57 | -1.59 | 10.73 | 3.099 | True | True |
