class Message:
    def __init__(self, message_id, source, message_type, priority, size):
        self.message_id = message_id
        self.source = source
        self.message_type = message_type
        self.priority = priority
        self.size = size