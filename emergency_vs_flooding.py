from message import Message
from pqc_manager import PQCManager
from secure_message import SecureMessage
from resource_monitor import ResourceMonitor
from admission_controller import AdmissionController


# ==================================================
# EMERGENCY VS FLOODING TEST
# ==================================================

print("========================================")
print("   EMERGENCY VS FLOODING TEST")
print("========================================")
print()


# --------------------------------------------------
# 1. SYSTEM CONFIGURATION
# --------------------------------------------------

relay_capacity = 5000

attacker_name = "AttackerUAV"


# --------------------------------------------------
# 2. CREATE SYSTEM COMPONENTS
# --------------------------------------------------

pqc = PQCManager()

monitor = ResourceMonitor(
    relay_capacity=relay_capacity
)

controller = AdmissionController(
    relay_capacity=relay_capacity
)


# --------------------------------------------------
# 3. FLOODING TRAFFIC
# --------------------------------------------------

print("========== ATTACKER TRAFFIC ==========")
print()

for i in range(1, 4):

    message_id = f"ATTACK-{i:03d}"

    attack_message = Message(
        message_id,
        attacker_name,
        "Flooding",
        1,
        100
    )

    secure_attack = SecureMessage(
        attack_message,
        pqc
    )

    bundle_size = (
        len(secure_attack.encapsulated_key)
        + len(secure_attack.nonce)
        + len(secure_attack.ciphertext)
    )

    current_buffer = monitor.buffer_used

    decision = controller.evaluate(
        message_priority=attack_message.priority,
        message_size=bundle_size,
        current_buffer_usage=current_buffer
    )

    print(
        f"{message_id} | "
        f"Priority: {attack_message.priority} | "
        f"Size: {bundle_size} bytes | "
        f"Decision: {decision}"
    )

    if decision == "ACCEPT":

        new_buffer_usage = (
            current_buffer + bundle_size
        )

        monitor.update_buffer(
            new_buffer_usage
        )

        monitor.record_message(
            bundle_size
        )

        monitor.record_pqc_processing(
            secure_attack.pqc_processing_time
        )

        print(
            f"Buffer: "
            f"{new_buffer_usage} / "
            f"{relay_capacity} bytes "
            f"({monitor.get_buffer_utilization():.2f}%)"
        )

    print()


# --------------------------------------------------
# 4. CHECK RESOURCE PRESSURE
# --------------------------------------------------

print("========== RESOURCE PRESSURE ==========")
print()

print(
    "Current buffer:",
    monitor.buffer_used,
    "/",
    relay_capacity,
    "bytes"
)

print(
    "Buffer utilization:",
    f"{monitor.get_buffer_utilization():.2f}%"
)

print(
    "Buffer status:",
    monitor.get_resource_state()["buffer_status"]
)

print()


# --------------------------------------------------
# 5. EMERGENCY MESSAGE ARRIVES
# --------------------------------------------------

print("========== EMERGENCY MESSAGE ==========")
print()

emergency_message = Message(
    "EMERGENCY-001",
    "UAV1",
    "Emergency",
    5,
    100
)

secure_emergency = SecureMessage(
    emergency_message,
    pqc
)

emergency_bundle_size = (
    len(secure_emergency.encapsulated_key)
    + len(secure_emergency.nonce)
    + len(secure_emergency.ciphertext)
)

current_buffer = monitor.buffer_used

print(
    "Emergency message generated."
)

print(
    "Priority:",
    emergency_message.priority
)

print(
    "Current buffer:",
    current_buffer,
    "/",
    relay_capacity,
    "bytes"
)

print(
    "Emergency bundle size:",
    emergency_bundle_size,
    "bytes"
)

print()


# --------------------------------------------------
# 6. ADMISSION DECISION
# --------------------------------------------------

emergency_decision = controller.evaluate(
    message_priority=emergency_message.priority,
    message_size=emergency_bundle_size,
    current_buffer_usage=current_buffer
)

print(
    "Admission decision:",
    emergency_decision
)

print()


# --------------------------------------------------
# 7. PROCESS EMERGENCY MESSAGE
# --------------------------------------------------

if emergency_decision == "ACCEPT":

    new_buffer_usage = (
        current_buffer
        + emergency_bundle_size
    )

    monitor.update_buffer(
        new_buffer_usage
    )

    monitor.record_message(
        emergency_bundle_size
    )

    monitor.record_pqc_processing(
        secure_emergency.pqc_processing_time
    )

    print(
        "SUCCESS!"
    )

    print(
        "Emergency message was ACCEPTED."
    )

    print(
        "Critical traffic was allowed "
        "despite resource pressure."
    )

    print(
        "New buffer utilization:",
        f"{monitor.get_buffer_utilization():.2f}%"
    )


elif emergency_decision == "DELAY":

    print(
        "Emergency message was DELAYED."
    )

elif emergency_decision == "THROTTLE":

    print(
        "Emergency message was THROTTLED."
    )

elif emergency_decision == "DROP":

    print(
        "WARNING!"
    )

    print(
        "Emergency message was DROPPED."
    )


# --------------------------------------------------
# 8. FINAL RESOURCE STATE
# --------------------------------------------------

print()
print("========================================")
print("       FINAL RESOURCE STATE")
print("========================================")

monitor.show_resource_state()


# --------------------------------------------------
# 9. TEST RESULT
# --------------------------------------------------

print()
print("========================================")
print("       TEST RESULT")
print("========================================")

if emergency_decision == "ACCEPT":

    print(
        "PASS: Critical emergency traffic "
        "was protected."
    )

else:

    print(
        "FAIL: Critical emergency traffic "
        "was not accepted."
    )


print()
print("========================================")
print("       TEST COMPLETED")
print("========================================")