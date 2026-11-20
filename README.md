# PQC-Aware Resource Protection for Intermittently Connected Mission-Critical Networks

This is a **synthetic software prototype** combining ML-KEM-768 key establishment, AES-256-GCM authenticated encryption, store-and-forward relay simulation, resource-aware admission decisions, message priority, and a Random Forest traffic classifier.

## Final candidate entry point

Use `ml_pqc_secure_dtn_experiment_v5.py` for the current all-gap implementation. `v2`, `v3`, and `v4` are retained as development history and should not be mixed with v5 result files.

Three approaches are compared:
1. **No Admission Protection** — still uses ML-KEM/AES-GCM, but does not use the protected admission policy/reserved emergency space.
2. **Rule-Based Protection**.
3. **ML + PQC-Aware Protection**.

## What v5 addresses

- **A — Resource monitoring:** the simulated model features remain estimates. If `psutil` is installed, v5 additionally records local host CPU/memory samples in `host_resource_samples.csv`. These are measurements of the computer running the script, not a UAV or radio; they are not fed into the model.
- **B — DELAY/THROTTLE:** DELAY bundles remain buffered until a later contact; THROTTLE bundles remain buffered and at most one throttled bundle can be forwarded per contact, within the contact's overall forwarding limit. Buffer bytes remain accounted for while queued. Bundles left after the last configured contact are reported as undelivered/queued, not delivered.
- **C — Baseline naming:** `No Admission Protection` clarifies that the baseline still uses PQC/AES-GCM.
- **D — ML versus policy evaluation:** v5 reports ML attack detection recall and benign false-positive rate separately from overall attack admission/delivery. Traffic labels are used for evaluation only, not as ML features or decision inputs.
- **E — Delay calculation:** delivery delay is computed from each configured contact start time minus message arrival time. This is still deterministic simulated delay, not measured physical network latency.

## Windows setup

Use Python 3.12. In Command Prompt, activate your existing venv and ensure `oqs.dll` is on PATH, for example:

```bat
set PATH=C:\liboqsin;%PATH%
python -m pip install -r requirements.txt
python -m py_compile ml_pqc_secure_dtn_experiment_v5.py
python ml_pqc_secure_dtn_experiment_v5.py
```

Run from the project folder containing `pqc_anomaly_detector.pkl`. The script writes `ml_pqc_secure_dtn_results.csv`, `ml_pqc_secure_dtn_decisions.csv`, and (if `psutil` is installed) `host_resource_samples.csv`. Regenerate these after the final run; older CSVs are historical snapshots.

## Scope and limitations

This is a synthetic DTN/UAV emergency-communication simulation, not a deployed UAV, a complete DTN protocol stack, or a real-time hardware benchmark. The resource-consumption feature is estimated from message size, buffer utilization and PQC timing. Host telemetry is local computer telemetry only. Contact schedules and delivery delays are simulated. The ML model can produce false negatives; do not tune against a small hand-designed stress test and present that as general accuracy. Keep held-out evaluation and designed-scenario results distinct.

A novel cryptographic algorithm is not claimed. The contribution is the integration and evaluation of PQC-aware resource policy, anomaly detection, intermittent forwarding, and priority handling in a synthetic scenario; the literature review must substantiate any broader novelty claim.
