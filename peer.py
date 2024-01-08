import logging
import struct
import threading
import time
from socket import *
import ssl
from colorama import Fore
import utility
from utility import format_message


# Server side of peer
class PeerServer(threading.Thread):

    # Peer server initialization
    def __init__(self, username, peerServerIP, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # Multicast configuration
        self.udp_socket = None
        self.multicast_group = '224.1.1.1'
        self.multicast_port = None
        self.group_session = False
        # One to One chatting
        self.private_udp_socket = socket(AF_INET, SOCK_DGRAM)
        self.private_udp_socket.bind((peerServerIP, peerServerPort))
        self.one_to_one_session = False

    # main method of the peer server thread
    def run(self):
        # Start the thread to receive One-to-One messages
        threading.Thread(target=self.receive_private_messages).start()
        while True:
            if self.group_session:
                self.receive_group_messages()

    def receive_group_messages(self):
        # Create a UDP socket for receiving multicast data
        self.udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # Allow multiple sockets to use the same port
        self.udp_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # Bind the socket to the multicast port
        self.udp_socket.bind(('', self.multicast_port))
        # Join the multicast group
        self.udp_socket.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, inet_aton(self.multicast_group)
                                   + inet_aton('0.0.0.0'))
        # Initial receive that you have joined
        self.udp_socket.recvfrom(1024)
        try:
            # Receive data
            while True:
                data, address = self.udp_socket.recvfrom(1024)
                self.output_data(data.decode())
        # handles the exceptions, and logs them
        except OSError as oErr:
            logging.error("OSError: {0}".format(oErr))
        except ValueError as vErr:
            logging.error("ValueError: {0}".format(vErr))
        finally:
            # Close the socket when done
            self.udp_socket.close()

    def output_data(self, data):
        data = format_message(data)
        sender = data.split(':')[0]
        if sender == "System" and data[-1] == '.':
            print(Fore.YELLOW + data)
        elif sender == "System" and data[-1] == '!':
            print(Fore.GREEN + data)
        elif sender != self.username:
            print(Fore.BLUE + data)

    def receive_private_messages(self):
        try:
            while True:
                data, address = self.private_udp_socket.recvfrom(1024)
                data = data.decode()
                # Process the received private message as needed
                if self.one_to_one_session:
                    self.output_data(data)
                elif not data.split(':')[0] == "System":
                    print(Fore.LIGHTMAGENTA_EX + "\nNotification: Received a private massage from " +
                          str(address) + " " + data)
        except Exception as e:
            logging.error(e)


# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, port, username, peerServer, chatroom_name, target_ip, target_port, target_username):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the username of the peer
        self.chatroom_name = chatroom_name
        # UDP socket for multicast
        self.udp_socket = None
        # Multicast address and port
        self.multicast_group = '224.1.1.1'
        self.multicast_port = port
        self.group_session = False
        # One-to-One
        self.target_ip = target_ip
        self.target_port = target_port
        self.target_username = target_username
        self.private_udp_socket = socket(AF_INET, SOCK_DGRAM)
        self.one_to_one_session = False

    # main method of the peer client thread
    def run(self):
        if self.one_to_one_session:
            self.chat()
        elif self.group_session:
            self.group_chat()

    def group_chat(self):
        # Create a UDP socket for multicast
        self.udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        # Allow multiple sockets to use the same port
        self.udp_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # Bind the socket to the multicast address and port
        self.udp_socket.bind(('', self.multicast_port))
        # Set the IP_MULTICAST_TTL option (time-to-live for packets)
        self.udp_socket.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, struct.pack('b', 1))

        message = "System: User " + self.username + " joined!"
        self.udp_socket.sendto(message.encode(), (self.multicast_group, self.multicast_port))
        print(Fore.RESET + "Welcome to Chatroom " + self.chatroom_name)
        print("Enter a message to send, enter 'q' to leave the room\n")
        while True:
            try:
                message = input()
                if message == 'q':
                    message = "System: User " + self.username + " left."
                    self.peerServer.udp_socket.close()
                    time.sleep(0.1)
                    self.udp_socket.sendto(message.encode(), (self.multicast_group, self.multicast_port))
                    self.udp_socket.close()
                    self.group_session = False
                    return
                message = self.username + ": " + message
                self.udp_socket.sendto(message.encode(), (self.multicast_group, self.multicast_port))
            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))

    def chat(self):
        print(Fore.RESET + "You are now chatting with " + self.target_username)
        print("Enter a message to send, enter 'q' to leave\n")
        while True:
            try:
                message = input()
                if message == 'q':
                    message = "System: User " + self.username + " left."
                    time.sleep(0.1)
                    self.private_udp_socket.sendto(message.encode(), (self.target_ip, self.target_port))
                    self.private_udp_socket.close()
                    self.one_to_one_session = False
                    return
                message = self.username + ": " + message
                self.private_udp_socket.sendto(message.encode(), (self.target_ip, self.target_port))

            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))

    def setup_private_chat(self, target_ip, target_port, target_username):
        self.target_ip = target_ip
        self.target_port = target_port
        self.target_username = target_username
        self.one_to_one_session = True

    def setup_group_chat(self, multicast_port, chatroom_name):
        self.multicast_port = multicast_port
        self.chatroom_name = chatroom_name
        self.group_session = True


# main process of the peer
class PeerUI:

    # peer initializations
    def __init__(self):
        # ip address of the registry
        self.registryName = input("Enter IP address of registry: ")
        # Create an instance of the main peer class
        self.main = PeerMain(self.registryName)
        # User Interface
        self.state = 0
        self.states = {1: "Welcome!", 2: "Main Menu"}
        self.options = {1: {1: "Signup", 2: "Login", 3: "Exit"},
                        2: {1: "Find Online Users", 2: "Search User", 3: "Create a Chat Room",
                            4: "Find Chat Rooms", 5: "Join a Chat Room", 6: "One to One chat", 7: "Logout"}}
        # as long as the user is not logged out, asks to select an option in the menu
        while True:
            # menu selection prompt
            if self.state == 0:
                print(Fore.MAGENTA + "P2P Chat Started")
                self.state = 1

            print(Fore.RESET + '\n' + self.states[self.state] + '\nSelect Option:')
            for option_number, option_name in self.options[self.state].items():
                print("\t" + str(option_number) + " : " + option_name)
            choice = input(Fore.MAGENTA + "\nChoice: ")
            self.handle_user_request(choice)

    def handle_user_request(self, choice):
        selection = self.options[self.state][int(choice)]

        if selection == "Signup":
            # Creates an account with the username and password entered by the user
            username = input(Fore.MAGENTA + "username: ")
            password = input(Fore.MAGENTA + "password: ")
            signup_status = self.main.createAccount(username, password)
            if signup_status == 1:
                print(Fore.GREEN + "Account created successfully.")
            elif signup_status == 2:
                print(Fore.YELLOW + "Username already exists. Choose another username or login.")
            elif signup_status == 3:
                print(Fore.RED + "Failed to create an account. Please try again.")
            time.sleep(1)

        elif selection == "Login":
            # Asks for the username and the password to login
            username = input(Fore.MAGENTA + "username: ")
            password = input(Fore.MAGENTA + "password: ")

            status = self.main.login(username, password)
            if status == 1:
                print(Fore.GREEN + "Logged in successfully...")
                self.state = 2
            elif status == 2:
                print(Fore.YELLOW + "Account is already online...")
            elif status == 3:
                print(Fore.RED + "The username or password are wrong, please try again...")
            time.sleep(0.5)

        elif selection == "Logout":
            # User is logged out and peer variables are set, and server and client sockets are closed
            self.main.logout(1)
            print(Fore.GREEN + "Logged out successfully")
            exit(0)

        elif selection == "Exit":
            # Exits the program:
            self.main.logout(2)
            exit(0)

        elif selection == "Find Online Users":
            # Prompt user for the users list mode and return it
            while True:
                option = input(Fore.MAGENTA + "Retrieve detailed list with users IP and Port numbers?(Choose y or n): ")
                if option == 'Y' or option == 'y':
                    self.main.find_online_user("DETAILED")
                    return
                elif option == 'N' or option == 'n':
                    self.main.find_online_user("SIMPLE")
                    return
                else:
                    print(Fore.RED + "Error: Please choose a valid option (y or n)\n")

        elif selection == "Search User":
            # The user is asked for a username that is wanted to be searched
            username = input(Fore.MAGENTA + "Username to be searched: ")
            search_status = self.main.search_user(username)
            # if user is found its ip address is shown to user
            if search_status is not None and search_status != 0:
                print(Fore.GREEN + "IP address:Port number of " + username + " is " + str(search_status))
                time.sleep(1)

        elif selection == "Create a Chat Room":
            while True:
                name = input(Fore.MAGENTA + "Chat room name: ")
                if name == 'quit':
                    break
                elif self.main.createChatroom(name):
                    break
                else:
                    print(Fore.RED + "A Chatroom with name " + name + " already exists!")
                    print(Fore.LIGHTGREEN_EX + "Hint: enter quit to return to main menu")
                    time.sleep(1)

        elif selection == "Find Chat Rooms":
            chat_rooms = self.main.findChatRooms()
            if len(chat_rooms) > 0:
                number = 1
                print(Fore.RESET + "#  Name".ljust(18) + "Host".ljust(15) + "Users in Chatroom")
                for chat_room in chat_rooms:
                    chat_room = str(chat_room).strip().split()
                    users = (str(chat_room[1:-1]).replace('[', '').replace(']', '')
                             .replace('\"', '').replace("\'", '')).replace(',,', ',')
                    print(Fore.GREEN + f"{number}  {chat_room[0]:15}{chat_room[-1]:15}{users}")
                    number += 1
            else:
                print(Fore.YELLOW + "No available Chat Rooms")
                time.sleep(1)

        elif selection == "Join a Chat Room":
            while True:
                name = input(Fore.MAGENTA + "Chat room name: ")
                if name == 'quit':
                    break
                elif self.main.joinChatroom(name):
                    break
                else:
                    print(Fore.RED + "No chatroom with the name " + name + "!")
                    print(Fore.LIGHTGREEN_EX + "Hint: enter quit to return to main menu")
                    time.sleep(1)

        elif selection == "show room peers":
            self.main.getRoomPeers()

        elif selection == "One to One chat":
            username = input(Fore.MAGENTA + "Username to chat with: ")
            if not self.main.create_private_chat(username):
                print(Fore.RED + "No online user with username " + username + " right now.")
                print(Fore.LIGHTGREEN_EX + "Hint: enter quit to return to main menu")
                time.sleep(1)

        else:
            print(Fore.RED + "Invalid Option Selected, please try again.\n")


class PeerMain:
    def __init__(self, registryName):
        self.registryName = registryName
        # port number of the registry
        self.registryPort = 15600
        # Initialize SSL connection
        self.tcpClientSocket = None
        self.ssl_connection()
        # initializes udp socket which is used to send hello messages
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # udp port of the registry
        self.registryUDPPort = 15500
        # login info of the peer
        self.loginCredentials = (None, None)
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # UDP Timer
        self.timer = None
        # Peer chatroom
        self.chatroom = None

    def ssl_connection(self):
        # tcp socket connection to registry
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # Create an SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Wrap the socket with SSL
        self.tcpClientSocket = context.wrap_socket(self.tcpClientSocket, server_hostname=self.registryName)
        # Connect to the server
        self.tcpClientSocket.connect((self.registryName, self.registryPort))
        self.connectServer()

    # account creation function
    def createAccount(self, username, password):
        # join message to create an account is composed and sent to registry
        # if response is "success" then informs the user for account creation
        # if response is "exist" then informs the user for account existence
        message = "REGISTER " + username + " " + utility.hash_password(password)
        response = self.send_credentials(message)
        # Process the response from the registry
        if response[2] == "<200>":
            return 1
        elif response[2] == "<300>":
            return 2
        elif response[2] == "<404>":
            return 3

    def send_credentials(self, message):
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        return response.split()

    # login function
    def login(self, username, password):
        # a login message is composed and sent to registry
        # an integer is returned according to each response
        message = "LOGIN " + username + " " + utility.hash_password(password)
        response = self.send_credentials(message)
        if response[2] == "<200>":
            # User logs in successfully, peer variables are set
            self.loginCredentials = (username, password)
            # hello message is sent to registry
            self.sendKeepAliveMessage(self.loginCredentials[0])
            search_status = self.search_user(username, False).split(":")
            self.peerServer = PeerServer(self.loginCredentials[0], search_status[0], int(search_status[1]))
            self.peerServer.start()
            return 1
        elif response[2] == "<300>":
            return 2
        elif response[2] == "<404>":
            return 3

    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + str(self.loginCredentials[0])
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        try:
            self.tcpClientSocket.send(message.encode())
            self.tcpClientSocket.close()
        except Exception as e:
            pass
        self.loginCredentials = (None, None)
        if self.peerServer is not None and self.peerServer.udp_socket is not None:
            self.peerServer.udp_socket.close()
        if self.peerClient is not None and self.peerClient.udp_socket is not None:
            self.peerClient.udp_socket.close()

    # function for searching an online user
    def search_user(self, username, output=True):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH_USER " + username
        response = self.exchange_messages(message)
        if response[2] == "<200>":
            if output:
                print(Fore.GREEN + username + " is found successfully...")
                time.sleep(1)
            return response[3]
        elif response[2] == "<300>":
            if output:
                print(Fore.YELLOW + username + " is not online...")
                time.sleep(1)
            return 0
        elif response[2] == "<404>":
            if output:
                print(Fore.RED + username + " is not found")
                time.sleep(1)
            return None

    def exchange_messages(self, message):
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        return response

    def find_online_user(self, option):
        message = "DISCOVER_PEERS " + option + " " + str(self.loginCredentials[0])
        response = self.exchange_messages(message)
        if response[2] == "<200>":
            response = response[3:]
            number = 1
            if option == "DETAILED":
                print(Fore.RESET + "#  Username".ljust(18) + "(IP:Port)")
                for i in range(0, len(response), 2):
                    print(Fore.GREEN + f"{number}  {response[i]:15}{response[i + 1]}")
                    number += 1
            else:
                print(Fore.RESET + "Username")
                for username in response:
                    print(Fore.GREEN + str(number) + "  " + username)
                    number += 1
            time.sleep(1)
        elif response[2] == "<404>":
            print(Fore.YELLOW + "No Online Users right now, please check back later")
            time.sleep(1)

    # function for sending hello message
    # a timer thread is used to send hello messages to udp socket of registry
    def sendKeepAliveMessage(self, username):
        message = "KEEP_ALIVE " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryUDPPort) + " -> " + message)
        self.udpClientSocket.sendto(message.encode(), (self.registryName, self.registryUDPPort))
        # Schedule the next hello message
        self.timer = threading.Timer(1, self.sendKeepAliveMessage, args=[username])
        self.timer.start()

    def connectServer(self):
        starting_message = "HELLO_P2P"
        response = self.exchange_messages(starting_message)
        status_code = int(response[2])
        if status_code == "<200>":
            print(Fore.GREEN + "Connected to the registry...")

    def createChatroom(self, name):
        message = "CREATE-CHAT-ROOM " + name + " " + str(self.loginCredentials[0])
        response = self.exchange_messages(message)
        status_code = response[2]
        if status_code == "<200>":
            self.chatroom = name
            print(Fore.GREEN + "A chatroom with name " + name + " has been created...\n")
            time.sleep(1)
            self.connect_to_chatroom(self.loginCredentials[0])
            return True
        else:
            return False

    def joinChatroom(self, name):
        message = "JOIN-CHAT-ROOM " + name + " " + str(self.loginCredentials[0])
        response = self.exchange_messages(message)
        status_code = response[2]
        if status_code == "<200>":
            print(Fore.GREEN + "You have joined the room " + name + " successfully...\n")
            time.sleep(0.5)
            self.chatroom = name
            self.connect_to_chatroom(response[3])
            return True
        return False

    def findChatRooms(self):
        chatrooms_list = []
        message = "SHOW-ROOM-LIST"
        response = self.exchange_messages(message)
        status_code = response[2]
        response = ' '.join(response)
        if status_code == "<200>":
            # Extract the list part from the received message
            list_start_index = response.find("<200>") + len("<200>")
            chatrooms_list_str = response[list_start_index:].strip()

            # Split the string into a list
            chatrooms_list = list(chatrooms_list_str.split('.'))[:-1]
            return chatrooms_list
        return chatrooms_list

    def exitChatroom(self, username):
        message = "ROOM-EXIT " + username + " " + self.chatroom
        response = self.exchange_messages(message)
        status_code = response[2]
        if status_code == "<200>":
            return True
        return False

    def connect_to_chatroom(self, host):
        search_status = self.search_user(host, False)
        # if searched user is found, then its port number is retrieved and a client thread is created
        if search_status and search_status != 0:
            search_status = search_status.split(":")
            # configure server thread to receive messages from the chatroom
            self.peerServer.multicast_port = int(search_status[1])
            self.peerServer.group_session = True
            self.peerClient = PeerClient(int(search_status[1]), self.loginCredentials[0], self.peerServer,
                                         self.chatroom, None, None, None)
            self.peerClient.start()
            self.peerClient.join()
            # Loop in the chatting until user exits
            self.peerClient.group_chat()
            # Exit from chatroom
            self.peerServer.group_session = False
            self.exitChatroom(self.loginCredentials[0])

    def getRoomPeers(self):
        room_peers = []
        message = "DISCOVER-ROOM-PEERS " + self.chatroom
        response = ' '.join(self.exchange_messages(message))
        status_code = response[2]
        if status_code == "<200>":
            # Assuming peers are present in the response starting from index 3
            list_start_index = response.find("<200>") + len("<200>")
            peer_list_str = response[list_start_index:].strip()

            # Split the string into a list
            room_peers = peer_list_str.split()

            # Print the chatrooms list

            print(Fore.CYAN, str(room_peers))
            return list(room_peers)
        return room_peers

    def create_private_chat(self, username):
        search_status = self.search_user(username, False)
        # if searched user is found, then its port number is retrieved and a client thread is created
        if search_status and search_status != 0:
            search_status = search_status.split(":")
            self.peerClient = PeerClient(int(search_status[1]), self.loginCredentials[0], self.peerServer,
                                         None, search_status[0], int(search_status[1]), username)
            self.peerClient.one_to_one_session = True
            self.peerServer.one_to_one_session = True
            self.peerClient.start()
            self.peerClient.join()
            self.peerServer.one_to_one_session = False
            self.peerClient.one_to_one_session = False
            return True
        return False


# log file initialization
logging.basicConfig(filename="logs/peer.log", level=logging.INFO)
# peer is started
main = PeerUI()
