
import os
import time
import json
import copy
import oqs

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class PQCDestination:
    """Destination owns its ML-KEM key pair and private key."""

    def __init__(self, name="CommandCenter"):
        self.name = name
        self.algorithm = "ML-KEM-768"
        self.kem = oqs.KeyEncapsulation(self.algorithm)
        self.public_key = self.kem.generate_keypair()
        self.received_messages = []
        self.received_ids = set()

    def decrypt_bundle(self, bundle):
        # Destination independently derives the shared secret.
        shared_secret = self.kem.decap_secret(
            bundle["encapsulated_key"]
        )

        plaintext = AESGCM(shared_secret).decrypt(
            bundle["nonce"],
            bundle["ciphertext"],
            bundle["aad"],
        )

        data = json.loads(plaintext.decode("utf-8"))
        return data

    def receive_bundle(self, bundle):
        """Authenticate, decrypt, and record a delivered message."""

        data = self.decrypt_bundle(bundle)

        message_id = data["message_id"]

        if message_id in self.received_ids:
            print(f"DUPLICATE IGNORED: {message_id}")
            return False

        received_at = time.perf_counter()
        delay = received_at - data["created_at"]

        self.received_ids.add(message_id)
        self.received_messages.append({
            "message_id": message_id,
            "message_type": data["message_type"],
            "priority": data["priority"],
            "created_at": data["created_at"],
            "received_at": received_at,
            "delay": delay,
        })

        print(
            f"DELIVERED: {message_id} | "
            f"Type: {data['message_type']} | "
            f"Priority: {data['priority']} | "
            f"Delay: {delay:.3f} seconds"
        )

        return True

    def close(self):
        self.kem.free()


class SecureSender:
    """Creates encrypted bundles for the destination public key."""

    def __init__(self, destination_public_key):
        self.algorithm = "ML-KEM-768"
        self.destination_public_key = destination_public_key

    def encrypt(self, message_id, source, message_type,
                priority, payload):
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")

        created_at = time.perf_counter()

        metadata = {
            "message_id": message_id,
            "source": source,
            "message_type": message_type,
            "priority": priority,
            "payload": payload,
            "created_at": created_at,
        }

        aad = (
            f"{message_id}|{source}|{message_type}|{priority}"
        ).encode("utf-8")

        plaintext = json.dumps(metadata).encode("utf-8")

        kem_start = time.perf_counter()

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            encapsulated_key, shared_secret = kem.encap_secret(
                self.destination_public_key
            )

        kem_time = time.perf_counter() - kem_start

        nonce = os.urandom(12)
        ciphertext = AESGCM(shared_secret).encrypt(
            nonce, plaintext, aad
        )

        return {
            "message_id": message_id,
            "priority": priority,
            "message_type": message_type,
            "encapsulated_key": encapsulated_key,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "aad": aad,
            "created_at": created_at,
            "pqc_processing_time": kem_time,
        }


class SecureDTNRelay:
    """Stores encrypted bundles and forwards them during contacts."""

    def __init__(self, name, capacity=5000):
        self.name = name
        self.capacity = capacity
        self.storage = []
        self.used_storage = 0

    @staticmethod
    def bundle_size(bundle):
        return (
            len(bundle["encapsulated_key"])
            + len(bundle["nonce"])
            + len(bundle["ciphertext"])
            + len(bundle["aad"])
        )

    def store(self, bundle):
        size = self.bundle_size(bundle)

        if self.used_storage + size > self.capacity:
            print(
                f"RELAY FULL: cannot store "
                f"{bundle['message_id']}"
            )
            return False

        self.storage.append(bundle)
        self.used_storage += size

        print(
            f"Stored encrypted {bundle['message_id']} "
            f"({size} bytes). "
            f"Buffer: {self.used_storage}/{self.capacity}"
        )
        return True

    def forward_contact(self, destination, link,
                        max_messages=None):
        """Forward only during an active contact."""

        if not link["connected"]:
            print("Cannot forward: link is disconnected.")
            return 0

        # Priority first; stable ordering for equal priorities.
        self.storage.sort(key=lambda item: -item["priority"])

        delivered_this_contact = 0
        remaining = []

        for bundle in self.storage:
            if (
                max_messages is not None
                and delivered_this_contact >= max_messages
            ):
                remaining.append(bundle)
                continue

            if not link["connected"]:
                remaining.append(bundle)
                continue

            try:
                success = destination.receive_bundle(bundle)

                if success:
                    self.used_storage -= self.bundle_size(bundle)
                    delivered_this_contact += 1
                else:
                    remaining.append(bundle)

            except InvalidTag:
                print(
                    f"AUTHENTICATION FAILED: "
                    f"{bundle['message_id']}; "
                    f"bundle was not delivered."
                )
                remaining.append(bundle)

            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                print(
                    f"INVALID BUNDLE: {bundle['message_id']}; "
                    f"bundle was not delivered."
                )
                remaining.append(bundle)

        self.storage = remaining

        print(
            f"Contact complete: {delivered_this_contact} delivered; "
            f"{len(self.storage)} remain in relay."
        )
        return delivered_this_contact


def report_metrics(attempted, destination, relay):
    delivered_records = destination.received_messages
    delivered = len(delivered_records)

    delivery_ratio = (
        delivered / attempted * 100 if attempted else 0
    )

    delays = [record["delay"] for record in delivered_records]

    average_delay = sum(delays) / len(delays) if delays else 0

    emergency_attempted = sum(
        1 for record in ATTEMPTED_MESSAGES
        if record["message_type"].lower() == "emergency"
    )

    emergency_delivered = sum(
        1 for record in delivered_records
        if record["message_type"].lower() == "emergency"
    )

    emergency_ratio = (
        emergency_delivered / emergency_attempted * 100
        if emergency_attempted else 0
    )

    print("\n" + "=" * 58)
    print("SECURE DTN DELIVERY METRICS")
    print("=" * 58)
    print(f"Legitimate messages attempted: {attempted}")
    print(f"Messages delivered: {delivered}")
    print(f"Messages not delivered: {attempted - delivered}")
    print(f"Delivery ratio: {delivery_ratio:.2f}%")
    print(f"Average end-to-end delay: {average_delay:.3f} seconds")
    print(
        f"Emergency delivery: {emergency_delivered}/"
        f"{emergency_attempted} ({emergency_ratio:.2f}%)"
    )
    print(f"Messages remaining in relay: {len(relay.storage)}")
    print(f"Relay storage used: {relay.used_storage} bytes")
    print("=" * 58)


ATTEMPTED_MESSAGES = []


def main():
    global ATTEMPTED_MESSAGES

    print("=" * 58)
    print("INTERMITTENT PQC + SECURE DTN DELIVERY TEST")
    print("=" * 58)

    destination = PQCDestination()
    relay = SecureDTNRelay("Relay1", capacity=5000)
    link = {"connected": False}

    try:
        sender = SecureSender(destination.public_key)

        messages = [
            ("MSG001", "UAV1", "Emergency", 5,
             "Emergency medical assistance required."),
            ("MSG002", "UAV1", "Normal", 2,
             "Routine telemetry update."),
            ("MSG003", "UAV2", "Emergency", 5,
             "Critical rescue coordination required."),
        ]

        ATTEMPTED_MESSAGES = [
            {
                "message_id": item[0],
                "message_type": item[2],
            }
            for item in messages
        ]

        attempted = len(messages)
        total_pqc_time = 0.0
        stored_ids = set()

        # Phase 1: all messages are created during disconnection.
        print("\nPHASE 1: LINK DISCONNECTED")
        print("Messages are encrypted and queued at the relay.")

        for item in messages:
            bundle = sender.encrypt(*item)
            total_pqc_time += bundle["pqc_processing_time"]

            print(
                f"{bundle['message_id']}: "
                f"ML-KEM encapsulation "
                f"{bundle['pqc_processing_time']:.6f} seconds"
            )

            if relay.store(bundle):
                stored_ids.add(bundle["message_id"])

        print(f"\nQueued messages: {len(relay.storage)}")

        # This delay deliberately models an outage.
        # It is a simulated test interval, not a network emulator.
        print("\nSimulating 1-second disconnection...")
        time.sleep(1.0)

        # Phase 2: a short contact allows only one message.
        print("\nPHASE 2: SHORT CONTACT WINDOW")
        link["connected"] = True
        print("DTN link: CONNECTED")

        relay.forward_contact(
            destination, link, max_messages=1
        )

        # Phase 3: connection is lost again.
        print("\nPHASE 3: LINK DISCONNECTED AGAIN")
        link["connected"] = False
        print("DTN link: DISCONNECTED")

        print("Simulating another 1-second outage...")
        time.sleep(1.0)

        # Phase 4: a later contact forwards the remaining queue.
        print("\nPHASE 4: CONTACT RESTORED")
        link["connected"] = True
        print("DTN link: CONNECTED")

        relay.forward_contact(destination, link)

        # Phase 5: tampering test uses a separate test bundle.
        print("\nPHASE 5: CIPHERTEXT TAMPERING TEST")

        tamper_bundle = sender.encrypt(
            "TAMPER-TEST",
            "UAV1",
            "Test",
            1,
            "This message will be modified."
        )

        modified_bundle = copy.deepcopy(tamper_bundle)
        corrupted = bytearray(modified_bundle["ciphertext"])
        corrupted[0] ^= 1
        modified_bundle["ciphertext"] = bytes(corrupted)

        try:
            destination.decrypt_bundle(modified_bundle)
            print(
                "WARNING: modified ciphertext was not rejected."
            )
        except InvalidTag:
            print(
                "PASS: AES-GCM rejected modified ciphertext."
            )

        # Phase 6: report legitimate message results only.
        report_metrics(attempted, destination, relay)

        print(f"Total sender-side ML-KEM time: {total_pqc_time:.6f} s")
        print(
            "\nNote: this test simulates outage intervals and limits "
            "the first contact to one message. It does not model "
            "physical network conditions, bandwidth, or packet loss."
        )

    finally:
        destination.close()


if __name__ == "__main__":
    main()
