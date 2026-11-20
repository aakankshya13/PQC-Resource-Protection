import heapq
from message import Message


class PriorityQueue:
    def __init__(self):
        self.queue = []
        self.counter = 0

    def add_message(self, message):
        heapq.heappush(
            self.queue,
            (-message.priority, self.counter, message)
        )
        self.counter += 1

    def get_next_message(self):
        if not self.queue:
            return None

        return heapq.heappop(self.queue)[2]


queue = PriorityQueue()

spam = Message("MSG001", "UAV3", "Spam", 1, 100)
normal = Message("MSG002", "UAV2", "Normal", 2, 100)
emergency = Message("MSG003", "UAV1", "Emergency", 5, 100)

queue.add_message(spam)
queue.add_message(normal)
queue.add_message(emergency)


print("Processing order:")

while True:
    message = queue.get_next_message()

    if message is None:
        break

    print(message.message_id, message.message_type, message.priority)