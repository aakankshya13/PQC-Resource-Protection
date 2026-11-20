"""
PQC-Aware Resource Protection for Intermittently Connected
Mission-Critical Networks

Three approaches:
1. No Admission Protection (still uses PQC/AES-GCM)
2. Rule-Based Protection
3. ML + PQC-Aware Protection

Security:
- ML-KEM-768 key establishment
- AES-256-GCM authenticated encryption
- Destination-side decapsulation and authenticated decryption

Features are calculated from observed arrival timing, payload size,
buffer state, priority, and a resource estimate. The traffic_type label
is used only for evaluation metrics, never as an ML input or decision rule.

Run:
    python ml_pqc_secure_dtn_experiment_v4.py

The baseline still uses PQC/AES-GCM; it disables admission-protection policy. Host CPU/memory telemetry (if psutil is installed) describes only the machine running this script, not UAV hardware. Contact delays are simulated from configured contact times. This is not validated real-world UAV performance.
"""

import os
import json
import time
import random
import statistics
try:
    import psutil
except ImportError:
    psutil = None
from collections import deque
from dataclasses import dataclass, field

import oqs
import joblib
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_FILE = "pqc_anomaly_detector.pkl"
RESULTS_FILE = "ml_pqc_secure_dtn_results.csv"
HOST_METRICS_FILE = "host_resource_samples.csv"
DECISIONS_FILE = "ml_pqc_secure_dtn_decisions.csv"

PQC_ALGORITHM = "ML-KEM-768"
RELAY_CAPACITY = 5000
RESERVED_EMERGENCY_BYTES = 1800
CONTACT_WINDOWS = [3, 3, 3, 3]  # maximum messages forwarded per contact
# Simulated contact schedule: the relay is disconnected before these times.
# The current workload arrives between t=0.00s and t=1.70s, so network_available
# is correctly 0 for every arrival in this particular scenario.
CONTACT_START_TIMES_SECONDS = [3.0, 6.0, 9.0, 12.0]
CONTACT_DURATION_SECONDS = 0.5
RANDOM_SEED = 42
TRAFFIC_RATE_WINDOW_SECONDS = 0.25

# ML-KEM-768 encapsulation ciphertext + AES-GCM nonce + authentication tag.
# Payload bytes are counted separately; Python metadata/object overhead is not
# included in this simulated relay-buffer accounting.
KEM_CIPHERTEXT_BYTES = 1088
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
CRYPTO_OVERHEAD_BYTES = (
    KEM_CIPHERTEXT_BYTES + AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES
)

MODEL_FEATURES = [
    "traffic_rate",
    "message_size",
    "buffer_utilization",
    "pqc_processing_time",
    "resource_consumption",
    "message_priority",
    "network_available",
]

random.seed(RANDOM_SEED)


# ============================================================
# MODEL
# ============================================================

def load_anomaly_model():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(
            f"Cannot find {MODEL_FILE} in the current folder. "
            "Place this script alongside pqc_anomaly_detector.pkl."
        )

    saved = joblib.load(MODEL_FILE)
    if isinstance(saved, dict):
        model = saved.get("model")
        features = saved.get("features", MODEL_FEATURES)
    else:
        model = saved
        features = getattr(model, "feature_names_in_", MODEL_FEATURES)

    if model is None:
        raise ValueError("The saved model does not contain a valid model.")

    features = list(features)
    missing = set(MODEL_FEATURES) - set(features)
    if missing:
        raise ValueError(
            "Saved model is missing features: " + ", ".join(sorted(missing))
        )

    print("\n[MODEL] Anomaly detector loaded.")
    print("[MODEL] Features:", ", ".join(features))
    return model, features


def predict_traffic(model, features, values):
    row = pd.DataFrame([{name: values[name] for name in features}],
                       columns=features)
    prediction = str(model.predict(row)[0])
    confidence = 0.0
    if hasattr(model, "predict_proba"):
        confidence = float(max(model.predict_proba(row)[0]))
    return prediction, confidence


# ============================================================
# WORKLOAD
# ============================================================

@dataclass
class Message:
    message_id: str
    traffic_type: str       # Evaluation metadata only
    priority: int
    payload: bytes
    created_at: float
    arrival_time: float

    @property
    def is_emergency(self):
        return self.priority >= 5


def create_workload():
    """
    Attack burst uses short inter-arrival times. Emergency traffic
    arrives after the burst. Labels are retained only for evaluation.
    """
    workload = []

    for i in range(10):
        payload_size = random.randint(500, 1400)
        arrival = i * 0.05
        workload.append(Message(
            message_id=f"ATTACK-{i + 1:02d}",
            traffic_type="Flooding",
            priority=1,
            payload=(f"Simulated burst message {i + 1}: "
                     + "X" * payload_size).encode("utf-8"),
            created_at=arrival,
            arrival_time=arrival,
        ))

    emergency_payloads = [
        b"UAV emergency alert: medical assistance required.",
        b"UAV emergency alert: rescue team required.",
        b"UAV emergency alert: critical incident detected.",
    ]
    for i, payload in enumerate(emergency_payloads):
        arrival = 1.5 + i * 0.1
        workload.append(Message(
            message_id=f"EMERGENCY-{i + 1:02d}",
            traffic_type="Emergency",
            priority=5,
            payload=payload,
            created_at=arrival,
            arrival_time=arrival,
        ))

    return workload


# ============================================================
# PQC + AUTHENTICATED ENCRYPTION
# ============================================================

class SecureDestination:
    def __init__(self):
        # Keep this exact KEM instance alive so its private key remains
        # available for destination-side decapsulation.
        self.kem = oqs.KeyEncapsulation(PQC_ALGORITHM)
        self.public_key = self.kem.generate_keypair()
        self.received_messages = []

    def decrypt_bundle(self, bundle):
        metadata = bundle["metadata"]
        aad = json.dumps(metadata, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
        shared_secret = self.kem.decap_secret(bundle["encapsulated_key"])
        plaintext = AESGCM(shared_secret).decrypt(
            bundle["nonce"], bundle["ciphertext"], aad
        )
        result = {
            "message_id": metadata["message_id"],
            "traffic_type": metadata["traffic_type"],
            "priority": metadata["priority"],
            "payload": plaintext,
            "created_at": metadata["created_at"],
            "arrival_time": metadata["arrival_time"],
        }
        self.received_messages.append(result)
        return result

    def close(self):
        try:
            self.kem.free()
        except Exception:
            pass


def encrypt_message(message, destination):
    metadata = {
        "message_id": message.message_id,
        "traffic_type": message.traffic_type,
        "priority": message.priority,
        "created_at": message.created_at,
        "arrival_time": message.arrival_time,
    }
    aad = json.dumps(metadata, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")

    # Measure KEM encapsulation separately from AES-GCM so the reported
    # PQC processing time does not include symmetric encryption overhead.
    kem_start = time.perf_counter()
    with oqs.KeyEncapsulation(PQC_ALGORITHM) as sender_kem:
        encapsulated_key, shared_secret = sender_kem.encap_secret(
            destination.public_key
        )
    kem_elapsed = time.perf_counter() - kem_start

    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    ciphertext = AESGCM(shared_secret).encrypt(nonce, message.payload, aad)

    # Check the overhead assumption used by admission control against the
    # actual serialized cryptographic components for ML-KEM-768 + AES-GCM.
    if len(encapsulated_key) != KEM_CIPHERTEXT_BYTES:
        raise ValueError(
            f"Unexpected {PQC_ALGORITHM} encapsulation ciphertext size: "
            f"{len(encapsulated_key)} bytes; expected {KEM_CIPHERTEXT_BYTES}."
        )
    if len(nonce) != AES_GCM_NONCE_BYTES:
        raise ValueError("Unexpected AES-GCM nonce size.")
    if len(ciphertext) != len(message.payload) + AES_GCM_TAG_BYTES:
        raise ValueError("Unexpected AES-GCM ciphertext/tag size.")

    bundle_size = len(encapsulated_key) + len(nonce) + len(ciphertext)
    expected_bundle_size = len(message.payload) + CRYPTO_OVERHEAD_BYTES
    if bundle_size != expected_bundle_size:
        raise ValueError(
            f"Buffer-size estimate mismatch: estimated {expected_bundle_size}, "
            f"actual {bundle_size} bytes."
        )

    return {
        "message_id": message.message_id,
        "traffic_type": message.traffic_type,
        "priority": message.priority,
        "created_at": message.created_at,
        "metadata": metadata,
        "encapsulated_key": encapsulated_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "size": bundle_size,
        "pqc_processing_time": kem_elapsed,
    }


# ============================================================
# OBSERVED TRAFFIC FEATURES
# ============================================================

class ObservedTrafficMonitor:
    """Counts arrival timestamps within a sliding window; no labels read."""

    def __init__(self, window_seconds=TRAFFIC_RATE_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.arrivals = deque()

    def observe(self, timestamp):
        timestamp = float(timestamp)
        self.arrivals.append(timestamp)
        cutoff = timestamp - self.window_seconds
        while self.arrivals and self.arrivals[0] < cutoff:
            self.arrivals.popleft()
        return len(self.arrivals) / self.window_seconds


def is_network_available(timestamp):
    """Return link availability from the explicit simulated contact schedule."""
    timestamp = float(timestamp)
    return int(any(
        start <= timestamp < start + CONTACT_DURATION_SECONDS
        for start in CONTACT_START_TIMES_SECONDS
    ))


def extract_observed_features(message, monitor, buffer_utilization,
                              pqc_processing_estimate):
    rate = monitor.observe(message.arrival_time)
    size = len(message.payload)

    # Keep resource_consumption on the 10-100 scale used by the
    # synthetic training data. This estimate uses measurable workload
    # factors only, not traffic_type or the target label.
    size_component = min(1.0, size / 1500.0)
    buffer_component = min(1.0, max(0.0, buffer_utilization / 100.0))
    pqc_component = min(1.0, max(0.0, pqc_processing_estimate / 0.0015))
    resource_consumption = min(
        100.0,
        max(10.0,
            10.0 + 35.0 * size_component
            + 35.0 * buffer_component
            + 20.0 * pqc_component)
    )

    return {
        "traffic_rate": float(rate),
        "message_size": int(size),
        "buffer_utilization": float(buffer_utilization),
        "pqc_processing_time": float(pqc_processing_estimate),
        "resource_consumption": float(resource_consumption),
        "message_priority": int(message.priority),
        "network_available": is_network_available(message.arrival_time),
    }


# ============================================================
# RELAY
# ============================================================

@dataclass
class Relay:
    capacity: int
    reserve_emergency_space: bool = False
    priority_eviction: bool = False
    reserved_emergency_bytes: int = RESERVED_EMERGENCY_BYTES
    queue: list = field(default_factory=list)
    buffer_used: int = 0
    peak_buffer: int = 0
    evicted_messages: list = field(default_factory=list)
    authentication_failures: int = 0

    def can_store_estimate(self, size, priority):
        if size > self.capacity:
            return False
        if (self.reserve_emergency_space and priority < 5
                and self.buffer_used + size
                > self.capacity - self.reserved_emergency_bytes):
            return False
        if self.buffer_used + size <= self.capacity:
            return True
        if not (self.priority_eviction and priority >= 5):
            return False

        available = self.buffer_used
        removable = sorted(
            [x for x in self.queue if x["priority"] < priority],
            key=lambda x: (x["priority"], x["created_at"]),
        )
        for victim in removable:
            available -= victim["size"]
            if available + size <= self.capacity:
                return True
        return False

    def store(self, bundle):
        size = bundle["size"]
        priority = bundle["priority"]
        if size > self.capacity:
            return False

        if (self.reserve_emergency_space and priority < 5
                and self.buffer_used + size
                > self.capacity - self.reserved_emergency_bytes):
            return False

        if self.buffer_used + size > self.capacity:
            if not (self.priority_eviction and priority >= 5):
                return False
            while self.buffer_used + size > self.capacity:
                candidates = [x for x in self.queue if x["priority"] < priority]
                if not candidates:
                    return False
                victim = min(candidates,
                             key=lambda x: (x["priority"], x["created_at"]))
                self.queue.remove(victim)
                self.buffer_used -= victim["size"]
                self.evicted_messages.append(victim["message_id"])

        if self.buffer_used + size > self.capacity:
            return False
        self.queue.append(bundle)
        self.buffer_used += size
        self.peak_buffer = max(self.peak_buffer, self.buffer_used)
        return True

    def forward_contact(self, destination, limit, contact_index, contact_time):
        """Forward eligible bundles while preserving delayed/throttled work.

        DELAY bundles are not eligible until the next contact. THROTTLE bundles
        may forward at most one per contact, within the overall contact
        forwarding limit. Ineligible bundles remain in the relay buffer.
        """
        self.queue.sort(key=lambda x: (-x["priority"], x["created_at"]))
        delivered = []
        forwarded = 0
        throttled_forwarded = 0
        remaining = []

        for bundle in self.queue:
            if forwarded >= limit:
                remaining.append(bundle)
                continue
            if bundle.get("eligible_contact", 1) > contact_index:
                remaining.append(bundle)
                continue
            if bundle.get("admission_decision") == "THROTTLE" and throttled_forwarded >= 1:
                remaining.append(bundle)
                continue

            try:
                received = destination.decrypt_bundle(bundle)
                received["delivery_time"] = float(contact_time)
                delivered.append(received)
            except Exception as exc:
                self.authentication_failures += 1
                print("[SECURITY] Authentication/decryption failure:",
                      bundle["message_id"], type(exc).__name__)
            finally:
                self.buffer_used -= bundle["size"]
                forwarded += 1
                if bundle.get("admission_decision") == "THROTTLE":
                    throttled_forwarded += 1

        self.queue = remaining
        return delivered


# ============================================================
# POLICIES
# ============================================================

def rule_based_decision(features, priority):
    if priority >= 5:
        return "ACCEPT", "critical priority override"
    if features["traffic_rate"] >= 15:
        return "DROP", "observed rate threshold"
    if features["buffer_utilization"] >= 70:
        return "DROP", "buffer threshold"
    if features["resource_consumption"] >= 65:
        return "DROP", "resource threshold"
    if features["message_size"] >= 900:
        return "DROP", "message-size threshold"
    return "ACCEPT", "rule thresholds passed"


def ml_pqc_aware_decision(model, model_features, features, priority):
    prediction, confidence = predict_traffic(
        model, model_features, features
    )

    buffer = features["buffer_utilization"]
    resource = features["resource_consumption"]
    rate = features["traffic_rate"]

    # Rule 1: Preserve emergency-message priority.
    if priority >= 5:
        return (
            "ACCEPT", prediction, confidence,
            "critical priority override"
        )

    # Rule 2: Independent resource-protection guard.
    # This works even when ML predicts NORMAL.
    if buffer >= 90 or resource >= 90:
        return (
            "THROTTLE", prediction, confidence,
            "independent high-resource guard"
        )

    # Rule 3: Reject traffic classified as anomalous by ML.
    if prediction in ("RESOURCE_EXHAUSTION", "SUSPICIOUS"):
        return (
            "DROP", prediction, confidence,
            "model anomaly prediction"
        )

    # Rule 4: Protect against unusually high observed traffic rates.
    if rate >= 15:
        return (
            "THROTTLE", prediction, confidence,
            "high observed traffic rate"
        )

    # Rule 5: Apply early resource-pressure control.
    if buffer >= 70 or resource >= 65:
        return (
            "DELAY", prediction, confidence,
            "early resource-pressure guard"
        )

    return (
        "ACCEPT", prediction, confidence,
        "ML and resource checks passed"
    )


# ============================================================
# EXPERIMENT
# ============================================================

def run_experiment(approach, workload, model, model_features):
    print("\n" + "=" * 72)
    print("APPROACH:", approach)
    print("=" * 72)

    destination = SecureDestination()
    protected = approach != "No Admission Protection"
    relay = Relay(
        capacity=RELAY_CAPACITY,
        reserve_emergency_space=protected,
        priority_eviction=(approach == "ML + PQC-Aware"),
    )
    monitor = ObservedTrafficMonitor()

    stats = {
        "Approach": approach,
        "Attempted": 0, "Admitted": 0, "Rejected": 0,
        "Dropped": 0, "Delayed": 0, "Throttled": 0,
        "Attack Attempted": 0, "Attack Admitted": 0,
        "Attack Delivered": 0, "Emergency Attempted": 0,
        "Emergency Admitted": 0, "Emergency Delivered": 0,
        "Delivered": 0, "Authentication Failures": 0,
        "Evicted Messages": 0, "Peak Buffer Bytes": 0,
        "Peak Buffer Utilization (%)": 0.0,
        "PQC Processing Time (s)": 0.0,
        "Average Simulated Delivery Delay (s)": 0.0,
        "ML Attack Detection Recall (%)": None,
        "ML Benign False Positive Rate (%)": None,
        "ML NORMAL Predictions": 0, "ML SUSPICIOUS Predictions": 0,
        "ML RESOURCE_EXHAUSTION Predictions": 0, "ML Decisions": 0,
    }
    decisions = []
    admitted_ids = set()
    delivered_ids = set()
    delays = []
    host_samples = []
    ml_attack_total = ml_attack_detected = 0
    ml_benign_total = ml_benign_flagged = 0

    calibration_time = 0.0004
    if approach == "ML + PQC-Aware":
        start = time.perf_counter()
        with oqs.KeyEncapsulation(PQC_ALGORITHM) as kem:
            pub = kem.generate_keypair()
            kem.encap_secret(pub)
        calibration_time = time.perf_counter() - start
        print(f"[CALIBRATION] KEM encapsulation: {calibration_time:.6f}s")

    for message in workload:
        stats["Attempted"] += 1
        # Traffic type is used here only to count ground-truth evaluation
        # outcomes; it is not supplied to feature extraction or policies.
        if message.traffic_type == "Flooding":
            stats["Attack Attempted"] += 1
        if message.is_emergency:
            stats["Emergency Attempted"] += 1

        buffer_pct = 100.0 * relay.buffer_used / relay.capacity
        # Optional real telemetry for the machine running this simulation.
        # This is host telemetry, NOT UAV/radio telemetry and is not fed to ML.
        if psutil is not None:
            try:
                host_samples.append({
                    "Approach": approach,
                    "Message ID": message.message_id,
                    "Host CPU Utilization (%)": float(psutil.cpu_percent(interval=None)),
                    "Host Memory Utilization (%)": float(psutil.virtual_memory().percent),
                    "Telemetry Source": "local host via psutil; not UAV telemetry",
                })
            except Exception:
                pass
        features = extract_observed_features(
            message, monitor, buffer_pct, calibration_time
        )

        prediction = "NOT_USED"
        confidence = 0.0

        if approach == "No Admission Protection":
            decision, reason = "ACCEPT", "no admission policy"
        elif approach == "Rule-Based":
            decision, reason = rule_based_decision(features, message.priority)
        else:
            decision, prediction, confidence, reason = ml_pqc_aware_decision(
                model, model_features, features, message.priority
            )
            stats["ML Decisions"] += 1
            if prediction == "NORMAL":
                stats["ML NORMAL Predictions"] += 1
            elif prediction == "SUSPICIOUS":
                stats["ML SUSPICIOUS Predictions"] += 1
            elif prediction == "RESOURCE_EXHAUSTION":
                stats["ML RESOURCE_EXHAUSTION Predictions"] += 1
            # Evaluation only: labels are not passed to prediction or policy.
            flagged = prediction in ("SUSPICIOUS", "RESOURCE_EXHAUSTION")
            if message.traffic_type == "Flooding":
                ml_attack_total += 1
                ml_attack_detected += int(flagged)
            else:
                ml_benign_total += 1
                ml_benign_flagged += int(flagged)

        estimated_size = len(message.payload) + CRYPTO_OVERHEAD_BYTES

        # This estimate must match the bundle's cryptographic bytes exactly:
        # 1088-byte ML-KEM-768 ciphertext + 12-byte nonce + 16-byte GCM tag
        # + original payload. Python metadata/object overhead is excluded.
        # encrypt_message() independently verifies this accounting on ACCEPT.

        # ACCEPT, DELAY, and THROTTLE all require real buffer admission.
        # Only DROP bypasses encryption/storage. Protected approaches also
        # preserve emergency reserve; priority-5 traffic can evict lower-priority
        # bundles in the ML + PQC-Aware relay when physically necessary.
        if decision != "DROP" and not relay.can_store_estimate(
                estimated_size, message.priority):
            if not (approach == "ML + PQC-Aware" and message.is_emergency):
                decision = "DROP"
                reason = "physical capacity/reservation"

        decisions.append({
            "Approach": approach,
            "Message ID": message.message_id,
            "Ground Truth (evaluation only)": message.traffic_type,
            **features,
            "Estimated Buffered Bytes": estimated_size,
            "Model Prediction": prediction,
            "Model Confidence": confidence,
            "Decision": decision,
            "Reason": reason,
        })

        if decision == "DROP":
            stats["Rejected"] += 1
            stats["Dropped"] += 1
            print(f"[DROP] {message.message_id:<15} "
                  f"rate={features['traffic_rate']:.1f}/s "
                  f"resource={features['resource_consumption']:.1f} "
                  f"prediction={prediction} reason={reason}")
            continue

        try:
            bundle = encrypt_message(message, destination)
        except Exception as exc:
            stats["Rejected"] += 1
            stats["Dropped"] += 1
            print("[ENCRYPTION FAILURE]", message.message_id, type(exc).__name__)
            continue

        # Queue policy metadata is relay-local and is deliberately excluded
        # from authenticated message metadata. DELAY waits one contact; THROTTLE
        # is limited to one forwarded throttled bundle per contact.
        bundle["admission_decision"] = decision
        bundle["eligible_contact"] = 2 if decision == "DELAY" else 1

        if not relay.store(bundle):
            stats["Rejected"] += 1
            stats["Dropped"] += 1
            print("[BUFFER REJECT]", message.message_id)
            continue

        stats["Admitted"] += 1
        stats["PQC Processing Time (s)"] += bundle["pqc_processing_time"]
        admitted_ids.add(message.message_id)
        if message.traffic_type == "Flooding":
            stats["Attack Admitted"] += 1
        if message.is_emergency:
            stats["Emergency Admitted"] += 1
        if decision == "DELAY":
            stats["Delayed"] += 1
        elif decision == "THROTTLE":
            stats["Throttled"] += 1

        label = "QUEUED FOR DELAY" if decision == "DELAY" else (
            "QUEUED FOR THROTTLED FORWARDING" if decision == "THROTTLE"
            else "ACCEPT")
        print(f"[{label}] {message.message_id:<15} priority={message.priority} "
              f"size={bundle['size']} buffer={relay.buffer_used}/{relay.capacity} "
              f"prediction={prediction} reason={reason}")

    evicted = set(relay.evicted_messages)
    stats["Evicted Messages"] = len(evicted)

    for contact_index, contact_limit in enumerate(CONTACT_WINDOWS, start=1):
        if not relay.queue:
            break
        eligible_count = sum(
            1 for bundle in relay.queue
            if bundle.get("eligible_contact", 1) <= contact_index
        )
        print(f"\n[DTN CONTACT {contact_index}] limit={contact_limit}, "
              f"queued={len(relay.queue)}, eligible={eligible_count}")
        contact_time = CONTACT_START_TIMES_SECONDS[contact_index - 1]
        for item in relay.forward_contact(destination, contact_limit, contact_index, contact_time):
            mid = item["message_id"]
            if mid in delivered_ids:
                continue
            delivered_ids.add(mid)
            stats["Delivered"] += 1
            if item["traffic_type"] == "Flooding":
                stats["Attack Delivered"] += 1
            if item["priority"] >= 5:
                stats["Emergency Delivered"] += 1
            # Deterministic simulated end-to-end delay from configured contact
            # start and message arrival. This is not measured physical latency.
            delay = max(0.0, item["delivery_time"] - item["arrival_time"])
            delays.append(delay)
            print(f"[DELIVERED] {mid} ({item['traffic_type']}) "
                  f"simulated_delay={delay:.3f}s")

    stats["Authentication Failures"] = relay.authentication_failures
    stats["Peak Buffer Bytes"] = relay.peak_buffer
    stats["Peak Buffer Utilization (%)"] = round(
        100.0 * relay.peak_buffer / relay.capacity, 2
    )
    stats["Average Simulated Delivery Delay (s)"] = (
        round(statistics.mean(delays), 4) if delays else 0.0
    )
    if approach == "ML + PQC-Aware":
        stats["ML Attack Detection Recall (%)"] = round(
            100.0 * ml_attack_detected / ml_attack_total, 2
        ) if ml_attack_total else None
        stats["ML Benign False Positive Rate (%)"] = round(
            100.0 * ml_benign_flagged / ml_benign_total, 2
        ) if ml_benign_total else None
    stats["Remaining Buffer Bytes"] = relay.buffer_used
    stats["Undelivered Admitted"] = len(admitted_ids - delivered_ids - evicted)
    if relay.queue:
        print(f"[END OF SIMULATION] {len(relay.queue)} bundle(s) remain queued "
              f"for a future contact; buffer={relay.buffer_used}/{relay.capacity} bytes")

    if host_samples:
        stats["Mean Host CPU Utilization (%)"] = round(
            statistics.mean(x["Host CPU Utilization (%)"] for x in host_samples), 2
        )
        stats["Mean Host Memory Utilization (%)"] = round(
            statistics.mean(x["Host Memory Utilization (%)"] for x in host_samples), 2
        )
    else:
        stats["Mean Host CPU Utilization (%)"] = None
        stats["Mean Host Memory Utilization (%)"] = None

    print("\n--- APPROACH SUMMARY ---")
    for key, value in stats.items():
        print(f"{key}: {value}")

    destination.close()
    return stats, decisions, host_samples


def main():
    print("=" * 72)
    print("PQC-AWARE RESOURCE PROTECTION EXPERIMENT")
    print("=" * 72)
    print("PQC algorithm:", PQC_ALGORITHM)
    print("Relay capacity:", RELAY_CAPACITY, "bytes")
    print("Emergency reserve:", RESERVED_EMERGENCY_BYTES, "bytes")
    print("Contact forwarding limits:", CONTACT_WINDOWS)
    print("Contact start times (s):", CONTACT_START_TIMES_SECONDS)
    print("Contact duration (s):", CONTACT_DURATION_SECONDS)
    print("Crypto overhead accounted per message:", CRYPTO_OVERHEAD_BYTES, "bytes")
    print("Resource telemetry:", "local host CPU/memory via psutil" if psutil else "simulated resource features only (psutil unavailable)")
    print("Baseline note: No Admission Protection still uses PQC/AES-GCM.")

    model, features = load_anomaly_model()
    workload = create_workload()
    print("\nWorkload summary:")
    print("Total messages:", len(workload))
    print("Attack messages:", sum(x.traffic_type == "Flooding" for x in workload))
    print("Emergency messages:", sum(x.is_emergency for x in workload))
    print("ML features are derived without reading traffic_type labels.")

    all_stats, all_decisions, all_host_samples = [], [], []
    for approach in ("No Admission Protection", "Rule-Based", "ML + PQC-Aware"):
        stats, decisions, host_samples = run_experiment(approach, workload, model, features)
        all_stats.append(stats)
        all_decisions.extend(decisions)
        all_host_samples.extend(host_samples)

    results = pd.DataFrame(all_stats)
    results.to_csv(RESULTS_FILE, index=False)
    pd.DataFrame(all_decisions).to_csv(DECISIONS_FILE, index=False)
    if all_host_samples:
        pd.DataFrame(all_host_samples).to_csv(HOST_METRICS_FILE, index=False)
        print("Host resource samples saved to:", HOST_METRICS_FILE)
    elif psutil is None:
        print("[INFO] Install psutil to collect optional local-host CPU/memory telemetry.")

    print("\n" + "=" * 72)
    print("FINAL COMPARISON")
    print("=" * 72)
    columns = [
        "Approach", "Attempted", "Admitted", "Rejected", "Delivered",
        "Attack Admitted", "Attack Delivered", "Emergency Delivered",
        "Authentication Failures", "Peak Buffer Utilization (%)",
        "PQC Processing Time (s)", "Average Simulated Delivery Delay (s)",
    ]
    print(results[columns].to_string(index=False))
    print("\nResults saved to:", RESULTS_FILE)
    print("Per-message decisions saved to:", DECISIONS_FILE)
    print("\nLIMITATION: synthetic workload and synthetic-data model. "
          "Traffic-type labels are used only to calculate evaluation metrics; "
          "the ML policy does not receive those labels. No real-world UAV "
          "detection or performance claim is established.")


if __name__ == "__main__":
    main()
