from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from resource_monitor import ResourceMonitor
from admission_controller import AdmissionController


# ==================================================
# FLOODING ATTACK WITH RESOURCE-AWARE PROTECTION
# ==================================================

print("========================================")
print("   FLOODING ATTACK + ADMISSION CONTROL")
print("========================================")
print()


# --------------------------------------------------
# 1. SYSTEM CONFIGURATION
# --------------------------------------------------

relay_capacity = 5000

number_of_messages = 10

attacker_name = "AttackerUAV"


# --------------------------------------------------
# 2. CREATE COMPONENTS
# --------------------------------------------------

pqc = PQCManager()

monitor = ResourceMonitor(
    relay_capacity=relay_capacity
)

controller = AdmissionController(
    relay_capacity=relay_capacity
)


# --------------------------------------------------
# 3. ATTACK INFORMATION
# --------------------------------------------------

print("Attacker:", attacker_name)

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
# 4. FLOODING SIMULATION
# --------------------------------------------------

accepted = 0
delayed = 0
throttled = 0
dropped = 0


for i in range(1, number_of_messages + 1):

    message_id = f"ATTACK-{i:03d}"

    # All attack messages are low priority.
    message = Message(
        message_id,
        attacker_name,
        "Flooding",
        1,
        100
    )

    # Create PQC-protected message.
    secure_message = SecureMessage(
        message,
        pqc
    )

    # Calculate complete encrypted bundle size.
    bundle_size = (
        len(secure_message.encapsulated_key)
        +
        len(secure_message.nonce)
        +
        len(secure_message.ciphertext)
    )

    # Current buffer usage BEFORE admission.
    current_buffer = monitor.buffer_used

    # Ask admission controller for decision.
    decision = controller.evaluate(

        message_priority=message.priority,

        message_size=bundle_size,

        current_buffer_usage=current_buffer
    )


    # --------------------------------------------------
    # PROCESS DECISION
    # --------------------------------------------------

    if decision == "ACCEPT":

        new_buffer_usage = (
            current_buffer
            + bundle_size
        )

        monitor.update_buffer(
            new_buffer_usage
        )

        monitor.record_message(
            bundle_size
        )

        monitor.record_pqc_processing(
            secure_message.pqc_processing_time
        )

        accepted += 1

        print(
            f"{message_id} | "
            f"Priority: {message.priority} | "
            f"Size: {bundle_size} bytes | "
            f"Decision: ACCEPT"
        )

        print(
            f"Buffer: "
            f"{new_buffer_usage} / "
            f"{relay_capacity} bytes "
            f"({monitor.get_buffer_utilization():.2f}%)"
        )


    elif decision == "DELAY":

        delayed += 1

        print(
            f"{message_id} | "
            f"Priority: {message.priority} | "
            f"Size: {bundle_size} bytes | "
            f"Decision: DELAY"
        )

        print(
            "Message is not admitted into the buffer."
        )


    elif decision == "THROTTLE":

        throttled += 1

        print(
            f"{message_id} | "
            f"Priority: {message.priority} | "
            f"Size: {bundle_size} bytes | "
            f"Decision: THROTTLE"
        )

        print(
            "Flooding traffic is restricted."
        )


    elif decision == "DROP":

        dropped += 1

        print(
            f"{message_id} | "
            f"Priority: {message.priority} | "
            f"Size: {bundle_size} bytes | "
            f"Decision: DROP"
        )

        print(
            "Low-priority flooding traffic rejected."
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
# 6. ADMISSION STATISTICS
# --------------------------------------------------

print()
print("========================================")
print("       ADMISSION STATISTICS")
print("========================================")

print(
    "Accepted:",
    accepted
)

print(
    "Delayed:",
    delayed
)

print(
    "Throttled:",
    throttled
)

print(
    "Dropped:",
    dropped
)

print(
    "Total generated:",
    number_of_messages
)


# --------------------------------------------------
# 7. FINAL RESULT
# --------------------------------------------------

print()
print("========================================")
print("       PROTECTION RESULT")
print("========================================")

final_utilization = (
    monitor.get_buffer_utilization()
)


print(
    "Final buffer utilization:",
    f"{final_utilization:.2f}%"
)


if final_utilization <= 100:

    print(
        "SUCCESS!"
    )

    print(
        "Relay buffer remained within capacity."
    )

else:

    print(
        "WARNING!"
    )

    print(
        "Relay buffer exceeded capacity."
    )


print()
print("========================================")
print("       PROTECTION TEST COMPLETED")
print("========================================")