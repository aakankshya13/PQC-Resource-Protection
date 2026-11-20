
import time
from pqc_manager import PQCManager


class SecureMessage:
    def __init__(self, message, pqc_manager, application_payload=None):
        self.message = message
        self.pqc_manager = pqc_manager

        if application_payload is None:
            application_payload = "Emergency message"

        if isinstance(application_payload, bytes):
            self.application_payload = application_payload
        elif isinstance(application_payload, str):
            self.application_payload = application_payload.encode("utf-8")
        else:
            raise TypeError(
                "Application payload must be a string or bytes."
            )

        (
            self.shared_secret,
            self.encapsulated_key,
            self.pqc_processing_time,
        ) = self.pqc_manager.establish_shared_secret()

        plaintext = self.create_plaintext()

        self.nonce, self.ciphertext = (
            self.pqc_manager.encrypt_message(
                plaintext, self.shared_secret
            )
        )

    def create_plaintext(self):
        header = (
            f"ID={self.message.message_id};"
            f"SOURCE={self.message.source};"
            f"TYPE={self.message.message_type};"
            f"PRIORITY={self.message.priority};"
            f"DATA_LENGTH={len(self.application_payload)};"
        ).encode("utf-8")

        return header + self.application_payload

    def decrypt(self):
        return self.pqc_manager.decrypt_message(
            self.nonce,
            self.ciphertext,
            self.shared_secret,
        )

    def encrypted_size(self):
        return len(self.ciphertext)

    def bundle_size(self):
        # Simplified bundle size: KEM ciphertext + nonce + encrypted data.
        return (
            len(self.encapsulated_key)
            + len(self.nonce)
            + len(self.ciphertext)
        )


if __name__ == "__main__":
    from message import Message

    manager = PQCManager()

    message = Message(
        "MSG001",
        "UAV1",
        "Emergency",
        5,
        300,
    )

    secure_message = SecureMessage(
        message,
        manager,
        application_payload="Emergency alert from UAV1",
    )

    decrypted = secure_message.decrypt()
    original = secure_message.create_plaintext().decode("utf-8")

    print("=" * 45)
    print("SECURE MESSAGE TEST")
    print("=" * 45)
    print("PQC algorithm:", manager.algorithm)
    print("Application payload size:", len(secure_message.application_payload), "bytes")
    print("Encrypted data size:", secure_message.encrypted_size(), "bytes")
    print("Complete simplified bundle size:", secure_message.bundle_size(), "bytes")
    print("Decryption successful:", decrypted == original)
