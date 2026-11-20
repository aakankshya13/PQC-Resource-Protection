
from message import Message
import time


class DTNDestination:
    """Represents the destination that receives forwarded messages."""

    def __init__(self, name):
        self.name = name
        self.received_messages = []
        self.received_ids = set()

    def receive_message(self, message, forwarded_at):
        """Record a message only if it has not already been received."""

        if message.message_id in self.received_ids:
            print(
                f"{message.message_id} already received at "
                f"{self.name}; duplicate ignored."
            )
            return False

        received_at = time.time()
        created_at = getattr(message, "created_at", forwarded_at)

        delivery_delay = max(0.0, received_at - created_at)

        self.received_ids.add(message.message_id)
        self.received_messages.append({
            "message_id": message.message_id,
            "message_type": message.message_type,
            "priority": message.priority,
            "delivery_delay_seconds": delivery_delay,
        })

        print(
            f"DELIVERED: {message.message_id} "
            f"received at {self.name} | "
            f"Priority: {message.priority} | "
            f"Delay: {delivery_delay:.4f} seconds"
        )
        return True

    def show_received(self):
        print(f"\nMessages received at {self.name}:")

        if not self.received_messages:
            print("No messages delivered yet.")
            return

        for record in self.received_messages:
            print(
                f"{record['message_id']} | "
                f"{record['message_type']} | "
                f"Priority: {record['priority']}"
            )


class DTNRelay:
    """Stores messages while the destination link is unavailable."""

    def __init__(self, name):
        self.name = name
        self.storage = []
        self.stored_ids = set()
        self.forwarded_count = 0

    def store_message(self, message):
        if message.message_id in self.stored_ids:
            print(
                f"{message.message_id} is already stored "
                f"at {self.name}."
            )
            return False

        self.storage.append(message)
        self.stored_ids.add(message.message_id)

        # Preserve the original creation time for delay measurement.
        if not hasattr(message, "created_at"):
            message.created_at = time.time()

        print(f"{message.message_id} stored at {self.name}")
        return True

    def show_storage(self):
        print(f"\nMessages currently stored at {self.name}:")

        if not self.storage:
            print("No messages in storage.")
            return

        for message in self.storage:
            print(
                f"{message.message_id} | "
                f"{message.message_type} | "
                f"Priority: {message.priority}"
            )

    def forward_messages(self, link, destination):
        if not link.connected:
            print("Cannot forward: DTN link is disconnected.")
            return

        if not self.storage:
            print("No messages to forward.")
            return

        print(
            f"\nForwarding {len(self.storage)} message(s) "
            f"from {self.name} to {destination.name}..."
        )

        # Process messages in descending priority order.
        # For equal priorities, preserve arrival order.
        self.storage.sort(key=lambda msg: -msg.priority)

        remaining = []

        for message in self.storage:
            if not link.connected:
                remaining.append(message)
                continue

            success = destination.receive_message(
                message, time.time()
            )

            if success:
                self.stored_ids.discard(message.message_id)
                self.forwarded_count += 1
            else:
                # Retain the message if destination receipt failed.
                remaining.append(message)

        self.storage = remaining

        print(
            f"Forwarding complete. Remaining in relay: "
            f"{len(self.storage)}"
        )


class DTNLink:
    """Simulates an intermittent connection."""

    def __init__(self):
        self.connected = False

    def connect(self):
        self.connected = True
        print("DTN link: CONNECTED")

    def disconnect(self):
        self.connected = False
        print("DTN link: DISCONNECTED")


def calculate_delivery_metrics(attempted_messages, destination):
    received = len(destination.received_messages)

    delivery_ratio = (
        received / attempted_messages * 100
        if attempted_messages else 0.0
    )

    delays = [
        record["delivery_delay_seconds"]
        for record in destination.received_messages
    ]

    average_delay = (
        sum(delays) / len(delays)
        if delays else 0.0
    )

    print("\n" + "=" * 48)
    print("DTN DELIVERY METRICS")
    print("=" * 48)
    print(f"Messages attempted: {attempted_messages}")
    print(f"Messages delivered: {received}")
    print(f"Messages not delivered: {attempted_messages - received}")
    print(f"Delivery ratio: {delivery_ratio:.2f}%")
    print(f"Average end-to-end delay: {average_delay:.4f} seconds")
    print("=" * 48)


# --------------------------------------------------
# TEST: DTN STORE-AND-FORWARD AND DESTINATION DELIVERY
# --------------------------------------------------

if __name__ == "__main__":
    relay = DTNRelay("Relay1")
    destination = DTNDestination("CommandCenter")
    link = DTNLink()

    test_messages = [
        Message("MSG001", "UAV1", "Emergency", 5, 100),
        Message("MSG002", "UAV1", "Normal", 2, 200),
        Message("MSG003", "UAV2", "Emergency", 5, 150),
    ]

    print("=" * 48)
    print("DTN STORE-AND-FORWARD DELIVERY TEST")
    print("=" * 48)

    print(f"Initial connection status: {link.connected}")

    # Simulate unavailable connectivity.
    print("\n1. Destination link is unavailable.")
    for message in test_messages:
        relay.store_message(message)

    relay.show_storage()
    destination.show_received()

    # Simulate connectivity returning.
    print("\n2. Connectivity returns.")
    link.connect()

    relay.forward_messages(link, destination)

    # Show final state and delivery metrics.
    print("\n3. Final relay state:")
    relay.show_storage()
    destination.show_received()

    calculate_delivery_metrics(
        len(test_messages),
        destination
    )
