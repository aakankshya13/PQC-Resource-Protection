from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from resource_monitor import ResourceMonitor


# ==================================================
# FLOODING ATTACK SIMULATION
# ==================================================

print("========================================")
print("       FLOODING ATTACK SIMULATION")
print("========================================")
print()


# --------------------------------------------------
# 1. CREATE PQC MANAGER
# --------------------------------------------------

pqc = PQCManager()


# --------------------------------------------------
# 2. CREATE RESOURCE MONITOR
# --------------------------------------------------

relay_capacity = 5000

monitor = ResourceMonitor(
    relay_capacity=relay_capacity
)


# --------------------------------------------------
# 3. ATTACKER PARAMETERS
# --------------------------------------------------

attacker_name = "AttackerUAV"

number_of_messages = 10

print(
    "Attacker:",
    attacker_name
)

print(
    "Messages generated:",
    number_of_messages
)

print(
    "Relay capacity:",
    relay_capacity,
    "bytes"
)

print()


# --------------------------------------------------
# 4. GENERATE FLOODING TRAFFIC
# --------------------------------------------------

for i in range(1, number_of_messages + 1):

    message_id = f"ATTACK-{i:03d}"

    message = Message(
        message_id,
        attacker_name,
        "Flooding",
        1,
        100
    )

    # Create PQC-protected message
    secure_message = SecureMessage(
        message,
        pqc
    )

    # Calculate encrypted bundle size
    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    # Record traffic
    monitor.record_message(
        bundle_size
    )

    # Update relay buffer
    new_buffer_usage = (
        monitor.buffer_used
        + bundle_size
    )

    monitor.update_buffer(
        new_buffer_usage
    )

    # Record PQC processing time
    monitor.record_pqc_processing(
        secure_message.pqc_processing_time
    )

    # Display attack traffic
    print(
        f"Message {i}: "
        f"{message_id} | "
        f"Size: {bundle_size} bytes"
    )

    print(
        f"Buffer usage: "
        f"{new_buffer_usage} / "
        f"{relay_capacity} bytes"
    )

    print(
        f"Buffer utilization: "
        f"{monitor.get_buffer_utilization():.2f}%"
    )

    print()


# --------------------------------------------------
# 5. FINAL RESOURCE STATE
# --------------------------------------------------

print("========================================")
print("       FINAL RESOURCE STATE")
print("========================================")

monitor.show_resource_state()


# --------------------------------------------------
# 6. ATTACK ANALYSIS
# --------------------------------------------------

print()
print("========================================")
print("       FLOODING ATTACK RESULT")
print("========================================")

final_utilization = (
    monitor.get_buffer_utilization()
)


if final_utilization >= 80:

    print(
        "WARNING: Relay resources are HIGHLY utilized."
    )

    print(
        "Potential resource exhaustion detected."
    )

elif final_utilization >= 50:

    print(
        "WARNING: Relay resources are moderately utilized."
    )

else:

    print(
        "Relay resources are currently within normal range."
    )


print()
print("========================================")
print("       FLOODING TEST COMPLETED")
print("========================================")