# Finite d=1 analytical parameter/cache table

Exact rational work; no measured timings; new performance samples: 0.
Signing includes independent REF self-verification in the `with self verify` column.

| Parameter | t | Signature B | Sign calls, no self verify | Sign calls, with self verify | Verify calls | Cache file B | Cache node RAM B |
|---|---:|---:|---:|---:|---:|---:|---:|
| pid3 | 10 | 3856 | 302270352.530704 | 302270630 | 277.469296 | 65632 | 131056 |
| pid3 | 12 | 3856 | 303112078.530704 | 303112356 | 277.469296 | 16480 | 32752 |
| rls128cs3 | 10 | 3920 | 44320656.530704 | 44320938 | 281.469296 | 65632 | 131056 |
| rls128cs3 | 12 | 3920 | 45162382.530704 | 45162664 | 281.469296 | 16480 | 32752 |
| rls128cs11 | 10 | 4016 | 12863376.530704 | 12863664 | 287.469296 | 65632 | 131056 |
| rls128cs11 | 12 | 4016 | 13705102.530704 | 13705390 | 287.469296 | 16480 | 32752 |
| rls128cs18 | 10 | 4048 | 3819408.530704 | 3819698 | 289.469296 | 65632 | 131056 |
| rls128cs18 | 12 | 4048 | 4661134.530704 | 4661424 | 289.469296 | 16480 | 32752 |

C_auth(12)-C_auth(10)=841726 logical calls; compression difference=893950.
The resource model is an explicit shape plus reserve, not measured peak RSS.
A/V elapsed costs remain unknown F_x, S_x, G_x; logical work does not rank execution modes.
Published neighbors are analytical candidates; full applicability and native adaptation remain pending.
