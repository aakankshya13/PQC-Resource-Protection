class AdmissionController:
    """
    Baseline resource-aware admission controller.

    Decisions:
        ACCEPT
        DELAY
        THROTTLE
        DROP
    """

    def __init__(self, relay_capacity):

        self.relay_capacity = relay_capacity

        # Reserve part of the buffer for
        # mission-critical traffic.
        self.critical_reserve = 0.20

    # ==================================================
    # ADMISSION DECISION
    # ==================================================

    def evaluate(
        self,
        message_priority,
        message_size,
        current_buffer_usage
    ):

        buffer_utilization = (
            current_buffer_usage
            / self.relay_capacity
        ) * 100

        # ----------------------------------------------
        # CRITICAL MESSAGE
        # ----------------------------------------------

        if message_priority >= 5:

            # Critical traffic gets the highest priority.
            # Allow it unless the message itself is
            # larger than the entire relay capacity.

            if message_size <= self.relay_capacity:

                return "ACCEPT"

            else:

                return "DROP"

        # ----------------------------------------------
        # HIGH PRIORITY
        # ----------------------------------------------

        elif message_priority >= 4:

            if buffer_utilization < 90:

                return "ACCEPT"

            elif buffer_utilization < 100:

                return "DELAY"

            else:

                return "DROP"

        # ----------------------------------------------
        # MEDIUM PRIORITY
        # ----------------------------------------------

        elif message_priority >= 2:

            if buffer_utilization < 70:

                return "ACCEPT"

            elif buffer_utilization < 90:

                return "DELAY"

            elif buffer_utilization < 100:

                return "THROTTLE"

            else:

                return "DROP"

        # ----------------------------------------------
        # LOW PRIORITY / SPAM
        # ----------------------------------------------

        else:

            if buffer_utilization < 50:

                return "ACCEPT"

            elif buffer_utilization < 70:

                return "DELAY"

            elif buffer_utilization < 90:

                return "THROTTLE"

            else:

                return "DROP"


# ==================================================
# TEST ADMISSION CONTROLLER
# ==================================================

print("========================================")
print("       ADMISSION CONTROLLER TEST")
print("========================================")
print()


controller = AdmissionController(
    relay_capacity=5000
)


# --------------------------------------------------
# TEST MESSAGES
# --------------------------------------------------

test_messages = [

    {
        "name": "Emergency Message",
        "priority": 5,
        "size": 1196
    },

    {
        "name": "High Priority Message",
        "priority": 4,
        "size": 1196
    },

    {
        "name": "Normal Message",
        "priority": 2,
        "size": 1196
    },

    {
        "name": "Flooding / Spam Message",
        "priority": 1,
        "size": 1196
    }

]


# --------------------------------------------------
# TEST DIFFERENT BUFFER CONDITIONS
# --------------------------------------------------

buffer_conditions = [
    0,
    2500,
    3500,
    4500,
    5000
]


for buffer_usage in buffer_conditions:

    print(
        "----------------------------------------"
    )

    print(
        "Current buffer:",
        buffer_usage,
        "/ 5000 bytes"
    )

    print()

    for message in test_messages:

        decision = controller.evaluate(

            message_priority=message["priority"],

            message_size=message["size"],

            current_buffer_usage=buffer_usage
        )

        print(
            message["name"],
            "| Priority:",
            message["priority"],
            "| Decision:",
            decision
        )


print()
print("========================================")
print("       ADMISSION TEST COMPLETED")
print("========================================")