import time

from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage


# ==================================================
# PQC OVERHEAD EXPERIMENT
# ==================================================

print("========================================")
print("       PQC OVERHEAD EXPERIMENT")
print("========================================")
print()


# --------------------------------------------------
# 1. CREATE PQC MANAGER
# --------------------------------------------------

pqc = PQCManager()

print("PQC Algorithm:", pqc.algorithm)
print()


# --------------------------------------------------
# 2. TEST DIFFERENT MESSAGE SIZES
# --------------------------------------------------

message_sizes = [
    100,
    300,
    500,
    1000,
    1500
]


results = []


# --------------------------------------------------
# 3. RUN EXPERIMENT
# --------------------------------------------------

for size in message_sizes:

    print("----------------------------------------")

    print(
        "Original message size:",
        size,
        "bytes"
    )

    # ----------------------------------------------
    # Create application message
    # ----------------------------------------------

    message = Message(
        f"MSG-{size}",
        "UAV1",
        "Normal",
        3,
        size
    )


    # ----------------------------------------------
    # Create plaintext payload
    # ----------------------------------------------

    plaintext = "A" * size


    # ----------------------------------------------
    # Measure ML-KEM processing
    # ----------------------------------------------

    start_time = time.perf_counter()

    (
        shared_secret,
        encapsulated_key,
        pqc_time
    ) = pqc.establish_shared_secret()

    key_establishment_time = (
        time.perf_counter() - start_time
    )


    # ----------------------------------------------
    # Encrypt application payload
    # ----------------------------------------------

    encryption_start = time.perf_counter()

    nonce, ciphertext = pqc.encrypt_message(
        plaintext,
        shared_secret
    )

    encryption_time = (
        time.perf_counter()
        - encryption_start
    )


    # ----------------------------------------------
    # Calculate secure bundle size
    # ----------------------------------------------

    secure_bundle_size = (
        len(encapsulated_key)
        +
        len(nonce)
        +
        len(ciphertext)
    )


    # ----------------------------------------------
    # Calculate overhead
    # ----------------------------------------------

    overhead_bytes = (
        secure_bundle_size
        - size
    )

    overhead_percentage = (
        overhead_bytes
        / size
    ) * 100


    # ----------------------------------------------
    # Store result
    # ----------------------------------------------

    results.append(
        {
            "original_size": size,
            "kem_size": len(encapsulated_key),
            "nonce_size": len(nonce),
            "encrypted_payload_size": len(ciphertext),
            "secure_bundle_size": secure_bundle_size,
            "overhead_bytes": overhead_bytes,
            "overhead_percentage": overhead_percentage,
            "pqc_time": pqc_time,
            "encryption_time": encryption_time
        }
    )


    # ----------------------------------------------
    # Display result
    # ----------------------------------------------

    print(
        "ML-KEM ciphertext:",
        len(encapsulated_key),
        "bytes"
    )

    print(
        "Nonce:",
        len(nonce),
        "bytes"
    )

    print(
        "Encrypted payload:",
        len(ciphertext),
        "bytes"
    )

    print(
        "Secure bundle:",
        secure_bundle_size,
        "bytes"
    )

    print(
        "PQC overhead:",
        overhead_bytes,
        "bytes"
    )

    print(
        "PQC overhead percentage:",
        f"{overhead_percentage:.2f}%"
    )

    print(
        "ML-KEM processing time:",
        f"{pqc_time:.6f}",
        "seconds"
    )

    print(
        "AES-GCM encryption time:",
        f"{encryption_time:.6f}",
        "seconds"
    )

    print()


# --------------------------------------------------
# 4. SUMMARY TABLE
# --------------------------------------------------

print("========================================")
print("       PQC OVERHEAD SUMMARY")
print("========================================")
print()

print(
    f"{'Original':<12}"
    f"{'KEM':<10}"
    f"{'Encrypted':<14}"
    f"{'Total':<12}"
    f"{'Overhead':<12}"
    f"{'Overhead %':<12}"
)

print(
    "-" * 70
)


for result in results:

    print(
        f"{result['original_size']:<12}"
        f"{result['kem_size']:<10}"
        f"{result['encrypted_payload_size']:<14}"
        f"{result['secure_bundle_size']:<12}"
        f"{result['overhead_bytes']:<12}"
        f"{result['overhead_percentage']:.2f}%"
    )


# --------------------------------------------------
# 5. AVERAGE PROCESSING TIME
# --------------------------------------------------

average_pqc_time = (
    sum(
        result["pqc_time"]
        for result in results
    )
    /
    len(results)
)


average_encryption_time = (
    sum(
        result["encryption_time"]
        for result in results
    )
    /
    len(results)
)


print()

print(
    "Average ML-KEM processing time:",
    f"{average_pqc_time:.6f}",
    "seconds"
)

print(
    "Average AES-GCM encryption time:",
    f"{average_encryption_time:.6f}",
    "seconds"
)


# --------------------------------------------------
# 6. FINAL RESULT
# --------------------------------------------------

print()
print("========================================")
print("       PQC OVERHEAD TEST COMPLETED")
print("========================================")

print(
    "The experiment measured communication "
    "and processing overhead introduced by "
    "PQC-protected messages."
)

print()