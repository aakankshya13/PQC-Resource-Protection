class Node:
    def __init__(self, name, node_type, cpu_capacity, memory_capacity):
        self.name = name
        self.node_type = node_type
        self.cpu_capacity = cpu_capacity
        self.memory_capacity = memory_capacity


uav1 = Node("UAV1", "UAV", 50, 512)
relay1 = Node("Relay1", "DTN Relay", 100, 1024)

print(uav1.name, uav1.node_type, uav1.cpu_capacity, uav1.memory_capacity)
print(relay1.name, relay1.node_type, relay1.cpu_capacity, relay1.memory_capacity)