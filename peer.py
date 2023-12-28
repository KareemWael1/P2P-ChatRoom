import logging
import threading
import time
from socket import *
import ssl
import select
from colorama import Fore
import utility


# Server side of peer
class PeerServer(threading.Thread):

    # Peer server initialization
    def __init__(self, username, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None
        self.peerServerHostname = None

    # main method of the peer server thread
    def run(self):

        print(Fore.CYAN + "Peer server started...")
        time.sleep(1)

        # gets the ip address of this peer
        # first checks to get it for Windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macOS devices
        hostname = gethostname()
        try:
            self.peerServerHostname = gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

        # ip address of this peer
        # self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer
        self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))
        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # the server listens as long as there is a socket to listen in the "inputs" list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:
                            print(Fore.CYAN + self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        message_received = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(message_received))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(message_received) > 11 and message_received[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main
                            # process of the peer if the socket that we received the data belongs to the peer that we
                            # are chatting with, enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                message_received = message_received.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(message_received[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = message_received[2]
                                # prints prompt for the incoming chat request
                                print(Fore.CYAN + "Incoming chat request from " + self.chattingClientName + " >> ")
                                print(Fore.CYAN + "Enter <ACCEPT> to accept or <REJECT> to reject:  ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are
                            # chatting with and if the user is already chatting with someone else(isChatRequested =
                            # 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then isChatRequested is made 1 and then next messages will be
                        # shown to the peer of this server
                        elif message_received == "<ACCEPT>":
                            self.isChatRequested = 1
                        # if an REJECT message is received then isChatRequested is made 0 so that it can receive any
                        # other chat requests
                        elif message_received == "<REJECT>":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and
                        # if it is not an empty message, show this message to the user
                        elif message_received[:2] != ":q" and len(message_received) != 0:
                            print(self.chattingClientName + ": " + message_received)
                        # if the message received is a quit message ':q',
                        # makes isChatRequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif message_received[:2] == ":q":
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(message_received) == 2:
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(message_received) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")
            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))


# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False

    # main method of the peer client thread
    def run(self):
        print("Peer client started...")
        # connects to the server of other peer
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client
        # then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the
            # server this client connects
            request_message = "CHAT_REQUEST" + str(self.peerServer.peerServerPort) + " " + self.username
            # logs the chat request sent to other peer
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + request_message)
            # sends the chat request
            self.tcpClientSocket.send(request_message.encode())
            print("Request message " + request_message + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
            logging.info(
                "Received from " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + self.responseReceived)
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the
            # connected server
            if self.responseReceived[1] == "<ACCEPT>":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                self.chat()
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                        except BrokenPipeError as bpErr:
                            logging.error("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected
            # peer's server logs the message and then the socket is closed
            elif self.responseReceived[1] == "<REJECT>":
                self.peerServer.isChatRequested = 0
                print("client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
        # if the client is created with OK message it means that this is the client of receiver side peer, so it sends
        # an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == " CHAT_REQUEST_RESPONSE <ACCEPT> <200>" + self.username:
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            ok_message = "<ACCEPT>"
            self.tcpClientSocket.send(ok_message.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + ok_message)
            print("Client with ACCEPT message is created... and sending messages")
            # client can send messages as long as the server status is chatting
            self.chat()
            # if the server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                self.responseReceived = None
                self.tcpClientSocket.close()

    def chat(self):
        while self.peerServer.isChatRequested == 1:
            # message input prompt
            message_sent = input(self.username + ": ")
            # sends the message to the connected peer, and logs it
            self.tcpClientSocket.send(message_sent.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + message_sent)
            # if the quit message is sent, then the server status is changed to not chatting
            # and this is the side that is ending the chat
            if message_sent == ":q":
                self.peerServer.isChatRequested = 0
                self.isEndingChat = True
                break


# main process of the peer
class peerMain:

    # peer initializations
    def __init__(self):
        # ip address of the registry
        self.registryName = input("Enter IP address of registry: ")
        # self.registryName = 'localhost'
        # port number of the registry
        self.registryPort = 15600
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
        # initializes udp socket which is used to send hello messages
        self.udpClientSocket = socket(AF_INET, SOCK_DGRAM)
        # udp port of the registry
        self.registryUDPPort = 15500
        # login info of the peer
        self.loginCredentials = (None, None)
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None
        self.chatroom = None
        # User Interface
        self.state = 0
        self.states = {1: "Welcome!", 2: "Main Menu", 3: "Chat room"}
        self.options = {1: {1: "Signup", 2: "Login", 3: "Exit"},
                        2: {1: "Find Online Users", 2: "Search User", 3: "Start a Chat",
                            4: "Create a Chat Room", 5: "Find Chat Rooms", 6: "Join a Chat Room",
                            7: "Logout"},
                        3: {1: "Send message", 2: "Leave room"}}

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
            username = input("username: ")
            password = input("password: ")
            self.createAccount(username, password)

        elif selection == "Login" and not self.isOnline:
            # Asks for the username and the password to login
            username = input("username: ")
            password = input("password: ")
            # asks for the port number for server's tcp socket
            peer_server_port = int(input("Enter a port number for peer server: "))

            status = self.login(username, password, peer_server_port)
            # is user logs in successfully, peer variables are set
            if status == 1:
                self.isOnline = True
                self.loginCredentials = (username, password)
                self.peerServerPort = peer_server_port
                # creates the server thread for this peer, and runs it
                self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort)
                self.peerServer.start()
                # hello message is sent to registry
                self.sendKeepAliveMessage(self.loginCredentials[0])
                self.state = 2

        elif selection == "Logout":
            # User is logged out and peer variables are set, and server and client sockets are closed
            if self.isOnline:
                self.logout(1)
                self.isOnline = False
                self.loginCredentials = (None, None)
                self.peerServer.isOnline = False
                self.peerServer.tcpServerSocket.close()
                if self.peerClient is not None:
                    self.peerClient.tcpClientSocket.close()
                print(Fore.GREEN + "Logged out successfully")
                self.tcpClientSocket.close()
                exit(0)

        elif selection == "Exit":
            # Exits the program:
            self.logout(2)
            self.tcpClientSocket.close()
            exit(0)

        elif selection == "Find Online Users":
            # Prompt user for the users list mode and return it
            while True:
                option = input(Fore.MAGENTA + "Retrieve detailed list with users IP and Port numbers?(Choose y or n): ")
                if option == 'Y' or option == 'y':
                    self.find_online_user("DETAILED")
                    return
                elif option == 'N' or option == 'n':
                    self.find_online_user("SIMPLE")
                    return
                else:
                    print(Fore.RED + "Error: Please choose a valid option (y or n)\n")

        elif selection == "Search User":
            # If user is online, then user is asked for a username that is wanted to be searched
            if self.isOnline:
                username = input("Username to be searched: ")
                search_status = self.search_user(username)
                # if user is found its ip address is shown to user
                if search_status is not None and search_status != 0:
                    print(Fore.MAGENTA + "IP address of " + username + " is " + search_status)
                    time.sleep(1)

        elif selection == "Create a Chat Room":
            while True:
                name = input(Fore.MAGENTA + "Chat room name: ")
                if name == 'quit':
                    break
                elif self.createChatroom(name):
                    print(Fore.GREEN + "A chatroom with name : " + name + " has been created...")
                    self.state = 3
                    time.sleep(1)

                    break
                else:
                    print(Fore.RED + "A Chatroom with name " + name + " already exists!")
                    print(Fore.LIGHTGREEN_EX + "Hint: enter quit to return to main menu")
                    time.sleep(1)

        elif selection == "Find Chat Rooms":
            chat_rooms = self.findChatRooms()
            if len(chat_rooms) > 0:
                pass
                    #     number = 1
                    #     print(Fore.RESET + "#  Name".ljust(18) + "Host")
                    #     for i in range(0, len(chat_rooms), 2):
                    #         print(Fore.GREEN + f"{number}  {chat_rooms[i]:15}{chat_rooms[i + 1]}")
                    #         number += 1
            else:
                print(Fore.YELLOW + "No available Chat Rooms")
                time.sleep(1)

        elif selection == "Join a Chat Room":
            while True:
                name = input(Fore.MAGENTA + "Chat room name: ")
                if name == 'quit':
                    break
                elif self.joinChatroom(name):
                    self.state = 3
                    break
                else:
                    print(Fore.RED + "No chatroom with the name " + name + "!")
                    print(Fore.LIGHTGREEN_EX + "Hint: enter quit to return to main menu")
                    time.sleep(1)

        elif selection == "Start a Chat":
            # if user is online, then user is asked to enter the username of the user that is wanted to be chatted
            if self.isOnline:
                username = input("Enter the username of user to start chat: ")
                search_status = self.search_user(username)
                # if searched user is found, then its ip address and port number is retrieved
                # and a client thread is created
                # main process waits for the client thread to finish its chat
                if search_status and search_status != 0:
                    search_status = search_status.split(":")
                    self.peerClient = PeerClient(search_status[0], int(search_status[1]), self.loginCredentials[0],
                                                 self.peerServer, None)
                    self.peerClient.start()
                    self.peerClient.join()
        elif selection == "Leave room":

            if self.exitChatroom(self.loginCredentials[0]):
                self.state = 2
        # if this is the receiver side then it will get the prompt to accept an incoming request during the main
        # loop that's why response is evaluated in main process not the server thread even though the prompt is
        # printed by server if the response is ok then a client is created for this peer with the OK message and
        # that's why it will directly send an OK message to the requesting side peer server and waits for the
        # user input main process waits for the client thread to finish its chat
        elif choice == "<ACCEPT>" and self.isOnline:
            ok_message = "<ACCEPT> " + self.loginCredentials[0]
            logging.info("Send to " + self.peerServer.connectedPeerIP + " -> " + ok_message)
            self.peerServer.connectedPeerSocket.send(ok_message.encode())
            self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort,
                                         self.loginCredentials[0], self.peerServer, "<ACCEPT>")
            self.peerClient.start()
            self.peerClient.join()
        # if user rejects the chat request then reject message is sent to the requester side
        elif choice == "<REJECT>" and self.isOnline:
            self.peerServer.connectedPeerSocket.send("<REJECT>".encode())
            self.peerServer.isChatRequested = 0
            logging.info("Send to " + self.peerServer.connectedPeerIP + " -> REJECT")

        # if choice is cancel timer for hello message is cancelled
        elif choice == "CANCEL":
            self.timer.cancel()
        else:
            print(Fore.RED + "Invalid Option Selected, please try again.\n")

    # account creation function
    def createAccount(self, username, password):
        # join message to create an account is composed and sent to registry
        # if response is "success" then informs the user for account creation
        # if response is "exist" then informs the user for account existence
        message = "REGISTER " + username + " " + utility.hash_password(password)
        response = self.send_credentials(message)
        # Process the response from the registry

        if response[2] == "<200>":
            print(Fore.GREEN + "Account created successfully.")
            time.sleep(1)
        elif response[2] == "<300>":
            print(Fore.YELLOW + "Username already exists. Choose another username or login.")
            time.sleep(1)
        elif response[2] == "<404>":
            print(Fore.RED + "Failed to create an account. Please try again.")
            time.sleep(1)

    def send_credentials(self, message):
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        return response.split()

    # login function
    def login(self, username, password, peerServerPort):
        # a login message is composed and sent to registry
        # an integer is returned according to each response
        message = "LOGIN " + username + " " + utility.hash_password(password) + " " + str(peerServerPort)
        response = self.send_credentials(message)
        if response[2] == "<200>":
            print(Fore.GREEN + "Logged in successfully...")
            time.sleep(1)
            return 1
        elif response[2] == "<300>":
            print(Fore.YELLOW + "Account is already online...")
            time.sleep(1)
            return 2
        elif response[2] == "<404>":
            print(Fore.RED + "Wrong password...")
            time.sleep(1)
            return 3

    # logout function
    def logout(self, option):
        # a logout message is composed and sent to registry
        # timer is stopped
        if option == 1:
            message = "LOGOUT " + self.loginCredentials[0]
            self.timer.cancel()
        else:
            message = "LOGOUT"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())

    # function for searching an online user
    def search_user(self, username):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH_USER " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[2] == "<200>":
            print(Fore.GREEN + username + " is found successfully...")
            time.sleep(1)
            return response[3]
        elif response[2] == "<300>":
            print(Fore.YELLOW + username + " is not online...")
            time.sleep(1)
            return 0
        elif response[2] == "<404>":
            print(Fore.RED + username + " is not found")
            time.sleep(1)
            return None

    def find_online_user(self, option):
        message = "DISCOVER_PEERS " + option + " " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
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

        # Assuming you expect a response from the registry

        # Schedule the next hello message
        self.timer = threading.Timer(1, self.sendKeepAliveMessage, args=[username])
        self.timer.start()

    def connectServer(self):
        starting_message = "HELLO_P2P"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + starting_message)
        self.tcpClientSocket.send(starting_message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        status_code = int(response[2])
        if status_code == "<200>":
            print(Fore.GREEN + "Connected to the registry...")

    def createChatroom(self, name):
        message = "CREATE-CHAT-ROOM " + name +  " " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        status_code = response[2]
        if status_code == "<200>":
            self.chatroom = name
            return True
        else:


            return False
    def joinChatroom(self, name):
        message = "JOIN-CHAT-ROOM " + name + " " + self.loginCredentials[0]
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        status_code = response[2]
        if status_code == "<200>":
            print(Fore.GREEN,"you have joined the room " + name + " successfully...")
            self.chatroom = name
            return True
        print(Fore.RED, "you have failed to join " + name )

        return False

    def findChatRooms(self):
        chatrooms_list =[]
        message = "SHOW-ROOM-LIST"
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        status_code = response.split()[2]
        if status_code == "<200>":

            # Decode the bytes to a string

            # Extract the list part from the received message
            list_start_index = response.find("<200>") + len("<200>")
            chatrooms_list_str = response[list_start_index:].strip()

            # Split the string into a list
            chatrooms_list = chatrooms_list_str.split()

            # Print the chatrooms list

            print(Fore.CYAN, str(chatrooms_list))
            return list(chatrooms_list)

        return chatrooms_list

    def exitChatroom(self,username):
        message = "ROOM-EXIT " + username + " " + self.chatroom
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        status_code = response[2]
        if status_code == "<200>":
            return True
        return False


# log file initialization
logging.basicConfig(filename="logs/peer.log", level=logging.INFO)
# peer is started
main = peerMain()
