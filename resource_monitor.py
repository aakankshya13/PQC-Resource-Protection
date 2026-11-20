import time


class ResourceMonitor:
    """
    Monitors resource usage related to
    PQC-protected DTN traffic.
    """

    def __init__(self, relay_capacity):

        self.relay_capacity = relay_capacity

        # Current relay buffer usage
        self.buffer_used = 0

        # Traffic statistics
        self.total_messages = 0
        self.total_bytes = 0

        # PQC statistics
        self.total_pqc_time = 0.0

    # ==================================================
    # BUFFER MONITORING
    # ==================================================

    def update_buffer(self, buffer_used):

        self.buffer_used = buffer_used

    def get_buffer_utilization(self):

        if self.relay_capacity == 0:
            return 0

        return (
            self.buffer_used
            / self.relay_capacity
        ) * 100

    # ==================================================
    # TRAFFIC MONITORING
    # ==================================================

    def record_message(self, message_size):

        self.total_messages += 1

        self.total_bytes += message_size

    # ==================================================
    # PQC MONITORING
    # ==================================================

    def record_pqc_processing(self, processing_time):

        self.total_pqc_time += processing_time

    # ==================================================
    # RESOURCE STATE
    # ==================================================

    def get_resource_state(self):

        buffer_utilization = (
            self.get_buffer_utilization()
        )

        if buffer_utilization < 50:

            buffer_status = "LOW"

        elif buffer_utilization < 80:

            buffer_status = "MEDIUM"

        else:

            buffer_status = "HIGH"

        return {
            "buffer_used": self.buffer_used,
            "buffer_capacity": self.relay_capacity,
            "buffer_utilization": buffer_utilization,
            "buffer_status": buffer_status,
            "total_messages": self.total_messages,
            "total_bytes": self.total_bytes,
            "total_pqc_time": self.total_pqc_time
        }

    # ==================================================
    # DISPLAY RESOURCE STATE
    # ==================================================

    def show_resource_state(self):

        state = self.get_resource_state()

        print()
        print("========== RESOURCE MONITOR ==========")

        print(
            "Buffer usage:",
            f"{state['buffer_used']:.0f}",
            "/",
            state["buffer_capacity"],
            "bytes"
        )

        print(
            "Buffer utilization:",
            f"{state['buffer_utilization']:.2f}%",
        )

        print(
            "Buffer status:",
            state["buffer_status"]
        )

        print(
            "Total messages:",
            state["total_messages"]
        )

        print(
            "Total traffic:",
            state["total_bytes"],
            "bytes"
        )

        print(
            "Total PQC processing time:",
            f"{state['total_pqc_time']:.6f}",
            "seconds"
        )


# ==================================================
# TEST RESOURCE MONITOR
# ==================================================

print("========================================")
print("       RESOURCE MONITOR TEST")
print("========================================")
print()


# Create a monitor for a 5000-byte relay buffer

monitor = ResourceMonitor(
    relay_capacity=5000
)


# Simulate one encrypted bundle

encrypted_bundle_size = 1186

pqc_processing_time = 0.000330


# Record traffic

monitor.record_message(
    encrypted_bundle_size
)


# Record PQC processing cost

monitor.record_pqc_processing(
    pqc_processing_time
)


# Simulate the bundle occupying relay storage

monitor.update_buffer(
    encrypted_bundle_size
)


# Display current resource state

monitor.show_resource_state()


print()
print("========================================")
print("       RESOURCE MONITOR TEST COMPLETED")
print("========================================")