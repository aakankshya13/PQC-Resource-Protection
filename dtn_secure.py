from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage


class SecureDTNRelay:
    """
    DTN relay that stores and forwards encrypted messages.

    The relay does not decrypt the application message.
    It only stores and forwards the encrypted bundle.
    """

    def __init__(self, name, storage_capacity):
        self.name = name
        self.storage_capacity = storage_capacity
        self.storage = []
        self.used_storage = 0

    def store_message(self, secure_message):

        message_size = (
            len(secure_message.encapsulated_key)
            + len(secure_message.nonce)
            + len(secure_message.ciphertext)
        )

        if self.used_storage + message_size > self.storage_capacity:

            print("RELAY STORAGE FULL!")
            print(
                "Cannot store:",
                secure_message.message.message_id
            )

            return False

        self.storage.append(secure_message)
        self.used_storage += message_size

        print(
            f"{secure_message.message.message_id} "
            f"stored at {self.name}"
        )

        print(
            "Encrypted bundle size:",
            message_size,
            "bytes"
        )

        print(
            "Relay storage used:",
            self.used_storage,
            "/",
            self.storage_capacity,
            "bytes"
        )

        return True

    def show_storage(self):

        print()
        print("========== RELAY STORAGE ==========")

        if not self.storage:
            print("No encrypted bundles stored.")
            return

        for secure_message in self.storage:

            print(
                "Message ID:",
                secure_message.message.message_id
            )

            print(
                "Priority:",
                secure_message.message.priority
            )

            print(
                "Encrypted payload size:",
                len(secure_message.ciphertext),
                "bytes"
            )

            print(
                "Status: ENCRYPTED"
            )

            print()

    def forward_messages(self):

        if not self.storage:

            print("No encrypted bundles to forward.")
            return []

        print()
        print("========== DTN FORWARDING ==========")

        forwarded_messages = []

        while self.storage:

            secure_message = self.storage.pop(0)

            message_size = (
                len(secure_message.encapsulated_key)
                + len(secure_message.nonce)
                + len(secure_message.ciphertext)
            )

            self.used_storage -= message_size

            print(
                secure_message.message.message_id,
                "forwarded from",
                self.name,
                "to destination"
            )

            print(
                "Bundle remains encrypted during forwarding."
            )

            forwarded_messages.append(secure_message)

        return forwarded_messages


class DTNLink:
    """
    Simulates intermittent connectivity.
    """

    def __init__(self):
        self.connected = False

    def connect(self):

        self.connected = True

        print()
        print("DTN LINK: CONNECTED")

    def disconnect(self):

        self.connected = False

        print()
        print("DTN LINK: DISCONNECTED")


# ==================================================
# COMPLETE PQC + DTN TEST
# ==================================================

print("========================================")
print("       PQC + DTN INTEGRATION TEST")
print("========================================")
print()


# --------------------------------------------------
# 1. CREATE UAV MESSAGE
# --------------------------------------------------

message = Message(
    "MSG001",
    "UAV1",
    "Emergency",
    5,
    100
)

print("========== UAV MESSAGE ==========")

print("Message ID:", message.message_id)
print("Source:", message.source)
print("Type:", message.message_type)
print("Priority:", message.priority)

print()


# --------------------------------------------------
# 2. CREATE PQC MANAGER
# --------------------------------------------------

pqc = PQCManager()


# --------------------------------------------------
# 3. SECURE THE MESSAGE
# --------------------------------------------------

print("========== PQC PROTECTION ==========")

secure_message = SecureMessage(
    message,
    pqc
)

print(
    "Algorithm:",
    pqc.algorithm
)

print(
    "ML-KEM processing time:",
    f"{secure_message.pqc_processing_time:.6f}",
    "seconds"
)

print(
    "ML-KEM ciphertext size:",
    len(secure_message.encapsulated_key),
    "bytes"
)

print(
    "AES-GCM ciphertext size:",
    len(secure_message.ciphertext),
    "bytes"
)

print(
    "Nonce size:",
    len(secure_message.nonce),
    "bytes"
)

print()


# --------------------------------------------------
# 4. SHOW ENCRYPTED DATA
# --------------------------------------------------

print("========== ENCRYPTED BUNDLE ==========")

print(
    "Encrypted ciphertext:"
)

print(
    secure_message.ciphertext.hex()
)

print()

print(
    "The plaintext is NOT stored in the DTN relay."
)

print()


# --------------------------------------------------
# 5. CREATE DTN RELAY
# --------------------------------------------------

relay = SecureDTNRelay(
    "Relay1",
    storage_capacity=5000
)

link = DTNLink()


# --------------------------------------------------
# 6. SIMULATE DISCONNECTED NETWORK
# --------------------------------------------------

print("========== DTN TRANSMISSION ==========")

link.disconnect()

if link.connected:

    print(
        "Connection available. "
        "Sending encrypted bundle."
    )

else:

    print(
        "Connection unavailable."
    )

    print(
        "Storing encrypted bundle in DTN relay..."
    )

    relay.store_message(
        secure_message
    )


# --------------------------------------------------
# 7. SHOW RELAY STORAGE
# --------------------------------------------------

relay.show_storage()


# --------------------------------------------------
# 8. RESTORE CONNECTIVITY
# --------------------------------------------------

print("========== CONNECTION RESTORED ==========")

link.connect()


# --------------------------------------------------
# 9. FORWARD ENCRYPTED MESSAGE
# --------------------------------------------------

if link.connected:

    forwarded_messages = (
        relay.forward_messages()
    )


# --------------------------------------------------
# 10. DESTINATION DECRYPTION
# --------------------------------------------------

print()
print("========== DESTINATION ==========")

if forwarded_messages:

    received_message = (
        forwarded_messages[0]
    )

    print(
        "Encrypted bundle received."
    )

    print(
        "Decrypting at destination..."
    )

    decrypted_message = (
        received_message.decrypt()
    )

    print()

    print(
        "Recovered message:"
    )

    print(
        decrypted_message
    )

    print()

    if (
        "MSG001" in decrypted_message
        and
        "UAV1" in decrypted_message
    ):

        print("SUCCESS!")

        print(
            "PQC + DTN + encryption "
            "workflow verified."
        )

    else:

        print("ERROR!")

        print(
            "Message verification failed."
        )


print()
print("========================================")
print("       INTEGRATION TEST COMPLETED")
print("========================================")