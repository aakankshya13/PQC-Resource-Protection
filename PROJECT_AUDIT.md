# Project Audit — all five implementation gaps

## Current status

`ml_pqc_secure_dtn_experiment_v5.py` is the final candidate entry point intended to address the five gaps identified in the architecture review. It has passed Python syntax compilation in the authoring environment. The authoring environment does not have `liboqs` installed, so the full end-to-end cryptographic experiment was **not** run here. Run it in the user's configured Windows environment before treating the new outputs as validated.

## A. Resource monitoring

The model's `resource_consumption` remains an estimate derived from message size, buffer utilization and PQC timing. If `psutil` is installed, v5 additionally samples CPU and memory utilization of the host running the simulation and writes `host_resource_samples.csv`. These host values are supplementary observations and are not UAV/radio telemetry or ML inputs. Actual UAV CPU, energy, radio bandwidth, packet loss and memory-pressure measurements remain outside this software simulation.

## B. DELAY and THROTTLE

A DELAY bundle is stored in the relay and marked eligible from the next contact. A THROTTLE bundle is stored and at most one throttled bundle is forwarded per contact, within the overall forwarding limit. Buffer usage is retained while bundles wait. Messages still in the relay after the final configured contact are not counted as delivered. This is a simple simulation policy, not a production scheduler or token-bucket rate limiter.

## C. Baseline terminology

The baseline is named `No Admission Protection`. It still uses ML-KEM-768 and AES-GCM for accepted messages; it lacks the protected admission policy, emergency reserve and priority-eviction policy. It must not be described as “no cryptography”.

## D. Separate ML detection from system policy

The v5 summary reports ML attack-detection recall and benign false-positive rate for the ML approach. These use traffic-type labels strictly for post-hoc evaluation; labels are not model inputs or decision rules. Overall attack delivery/suppression also depends on admission rules, reserve/capacity limits, eviction and contact scheduling. These are different metrics and must be reported separately. The saved-model stress test previously classified 10/12 designed scenarios correctly, with false negatives S03 and R04; those 12 scenarios are not population estimates.

## E. Contact timing and delay

Delivery delay is computed using the configured contact start time for the forwarding contact minus the message arrival time. It is a deterministic simulated delay, not a measured wall-clock or real-network latency. All results depend on the configured contact schedule and synthetic workload.

## Required Windows verification

1. Set the correct `oqs.dll` PATH and activate the project venv.
2. Run `python -m py_compile ml_pqc_secure_dtn_experiment_v5.py`.
3. Run `python ml_pqc_secure_dtn_experiment_v5.py`.
4. Inspect the summary, all undelivered queued messages, emergency delivery, attack delivery, buffer accounting, authentication failures, ML recall/FPR, and all CSV outputs.
5. Compare results only from the same script version, workload, seed, and contact schedule.
6. Do not claim successful ML detection for attacks blocked only by capacity or admission rules.

## Scope boundary

This remains a synthetic research prototype. It is not validated on UAV hardware or radio links and is not production-ready. The integration may be a research contribution, but “first” or “novel algorithm” claims require independent literature verification.
