"""Focused unit test for DELAY and THROTTLE queue semantics in v5.

This test isolates relay scheduling from PQC so queue behaviour can be tested
without creating cryptographic keys. The main experiment remains unchanged.
"""
from ml_pqc_secure_dtn_experiment_v5 import Relay


class FakeDestination:
    def decrypt_bundle(self, bundle):
        return {
            "message_id": bundle["message_id"],
            "traffic_type": bundle.get("traffic_type", "Test"),
            "priority": bundle["priority"],
            "created_at": bundle["created_at"],
            "arrival_time": bundle.get("arrival_time", 0.0),
        }


def make_bundle(message_id, decision, eligible_contact=1, priority=1, created_at=0.0, size=100):
    return {
        "message_id": message_id,
        "traffic_type": "Test",
        "priority": priority,
        "created_at": created_at,
        "arrival_time": created_at,
        "size": size,
        "admission_decision": decision,
        "eligible_contact": eligible_contact,
    }


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS:", message)


def main():
    destination = FakeDestination()

    print("\nTEST 1: DELAY waits until the next contact")
    relay = Relay(capacity=1000)
    delayed = make_bundle("DELAY-01", "DELAY", eligible_contact=2)
    check(relay.store(delayed), "DELAY bundle stored")
    first = relay.forward_contact(destination, limit=3, contact_index=1, contact_time=1.0)
    check(len(first) == 0, "DELAY bundle is not delivered at contact 1")
    check(len(relay.queue) == 1 and relay.buffer_used == 100,
          "DELAY bundle remains queued and occupies buffer after contact 1")
    second = relay.forward_contact(destination, limit=3, contact_index=2, contact_time=2.0)
    check([x["message_id"] for x in second] == ["DELAY-01"],
          "DELAY bundle is delivered at contact 2")
    check(len(relay.queue) == 0 and relay.buffer_used == 0,
          "DELAY bundle is removed and buffer accounting returns to zero")

    print("\nTEST 2: THROTTLE forwards at most one throttled bundle per contact")
    relay = Relay(capacity=1000)
    check(relay.store(make_bundle("THROTTLE-01", "THROTTLE", created_at=1.0)),
          "first THROTTLE bundle stored")
    check(relay.store(make_bundle("THROTTLE-02", "THROTTLE", created_at=2.0)),
          "second THROTTLE bundle stored")
    first = relay.forward_contact(destination, limit=3, contact_index=1, contact_time=3.0)
    check([x["message_id"] for x in first] == ["THROTTLE-01"],
          "only one THROTTLE bundle is delivered at contact 1")
    check(len(relay.queue) == 1 and relay.buffer_used == 100,
          "second THROTTLE bundle remains queued after contact 1")
    second = relay.forward_contact(destination, limit=3, contact_index=2, contact_time=6.0)
    check([x["message_id"] for x in second] == ["THROTTLE-02"],
          "remaining THROTTLE bundle is delivered at contact 2")
    check(len(relay.queue) == 0 and relay.buffer_used == 0,
          "THROTTLE queue drains and buffer accounting returns to zero")

    print("\nTEST 3: Higher-priority messages are forwarded first")
    relay = Relay(capacity=1000)
    relay.store(make_bundle("NORMAL-01", "ACCEPT", priority=1, created_at=1.0))
    relay.store(make_bundle("EMERGENCY-01", "ACCEPT", priority=5, created_at=2.0))
    delivered = relay.forward_contact(destination, limit=1, contact_index=1, contact_time=3.0)
    check([x["message_id"] for x in delivered] == ["EMERGENCY-01"],
          "emergency priority is served before normal traffic")
    check(len(relay.queue) == 1 and relay.queue[0]["message_id"] == "NORMAL-01",
          "normal message remains queued when contact limit is reached")

    print("\nRESULT: All focused DELAY/THROTTLE/priority queue tests passed.")
    print("NOTE: This is a queue-scheduling unit test with a fake destination; it does not test PQC or AES-GCM.")


if __name__ == "__main__":
    main()
