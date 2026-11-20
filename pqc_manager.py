
import os
import time
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PQCManager:
    def __init__(self):
        self.algorithm = "ML-KEM-768"

    def establish_shared_secret(self):
        start_time = time.perf_counter()

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            encapsulated_key, shared_secret_sender = kem.encap_secret(
                public_key
            )
            shared_secret_receiver = kem.decap_secret(encapsulated_key)

        end_time = time.perf_counter()
        processing_time = end_time - start_time

        if shared_secret_sender != shared_secret_receiver:
            raise ValueError("Shared secret verification failed.")

        return (
            shared_secret_sender,
            encapsulated_key,
            processing_time,
        )

    def encrypt_message(self, message, shared_secret):
        aes_gcm = AESGCM(shared_secret)
        nonce = os.urandom(12)

        if isinstance(message, str):
            plaintext = message.encode("utf-8")
        elif isinstance(message, bytes):
            plaintext = message
        else:
            raise TypeError("Message must be a string or bytes.")

        ciphertext = aes_gcm.encrypt(nonce, plaintext, None)

        return nonce, ciphertext

    def decrypt_message(self, nonce, ciphertext, shared_secret):
        aes_gcm = AESGCM(shared_secret)
        plaintext = aes_gcm.decrypt(nonce, ciphertext, None)

        # Preserve the existing string-returning interface.
        return plaintext.decode("utf-8")


if __name__ == "__main__":
    print("=" * 45)
    print("PQC SECURITY LAYER TEST")
    print("=" * 45)

    manager = PQCManager()

    secret, encapsulated_key, processing_time = (
        manager.establish_shared_secret()
    )

    original_message = "Emergency alert from UAV1"
    nonce, ciphertext = manager.encrypt_message(
        original_message, secret
    )
    decrypted_message = manager.decrypt_message(
        nonce, ciphertext, secret
    )

    print("PQC Algorithm:", manager.algorithm)
    print("Encapsulated key size:", len(encapsulated_key), "bytes")
    print("Original message:", original_message)
    print("Decrypted message:", decrypted_message)
    print("PQC processing time:", round(processing_time, 6), "seconds")
    print("Verification:", "SUCCESS" if original_message == decrypted_message else "FAILED")
