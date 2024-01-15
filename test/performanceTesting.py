import subprocess
import os
import time
from threading import Thread, Lock
import matplotlib.pyplot as plt


total_time = 0
max_time = 0
min_time = float('inf')  # Initialize min_time with positive infinity

class PeerThread(Thread):
    def __init__(self, peer_id, lock, time_taken_list):
        super().__init__()
        self.peer_id = peer_id
        self.lock = lock
        self.time_taken_list = time_taken_list

    def run(self):

      #with self.lock:
            global total_time
            global max_time
            global min_time
            response_file = f"response_file_{self.peer_id}"  # Unique filename for each peer

            print(f"Peer {self.peer_id} is waiting for the lock")

            start_time = time.time()
            print(f"Starting Peer {self.peer_id}")

            subprocess.Popen(["start", "cmd", "/c", "python", "peer.py"], shell=True)

            # Wait for the response file to be created
            while not os.path.exists(response_file):
                pass

            # Read the response from the file
            with open(response_file, "r") as file:
                response = file.read()

            end_time = time.time()
            print(f"Peer {self.peer_id} connected to the registry")
            print(f"Server response: {response}")
            with self.lock:
            # Calculate the time taken for this peer
                peer_time = end_time - start_time

            # Update total_time, max_time, and min_time

                total_time += peer_time
                if peer_time > max_time:
                    max_time = peer_time
                if peer_time < min_time:
                    min_time = peer_time

                print(f"Peer {self.peer_id} took {peer_time:.2f} seconds to connect")
                # Append the time taken to the shared list

                self.time_taken_list.append(peer_time)

# Rest of your code remains the same

num_peers = 1000
# Replace with the actual path to peer.py

# Record the start time
start_time = time.time()

# Create and start threads for each peer
threads = []
lock = Lock()  # Create a lock to synchronize threads
time_taken_list = []  # List to store time taken by each peer
for i in range(num_peers):
    thread = PeerThread(peer_id=i+1, lock=lock, time_taken_list=time_taken_list)
    thread.start()
    threads.append(thread)

# Wait for all threads to finish
for thread in threads:
    thread.join()

# Record the end time
end_time = time.time()

# Calculate the total time taken
allconnection_time = end_time - start_time

# Calculate the average time taken
average_time = total_time / num_peers

# Plot the graph
plt.plot(range(1, num_peers+1), time_taken_list, marker='o')
plt.xlabel('Number of Peers')
plt.ylabel('Time (seconds)')
plt.title('Time taken by each peer to connect')
plt.grid(True)
plt.show()
print(f"Total time {total_time:.2f} seconds")

print(f"All {num_peers} peers connected in {allconnection_time:.2f} seconds")
print(f"Average time taken per peer: {average_time:.2f} seconds")
print(f"Maximum time taken by a peer: {max_time:.2f} seconds")
print(f"Minimum time taken by a peer: {min_time:.2f} seconds")
