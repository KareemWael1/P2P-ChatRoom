import logging
import threading
import time
from socket import *
import ssl
from colorama import Fore
import utility


# main process of the peer
class peerClient:

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
        self.timer = None
        # User Interface
        self.state = 0
        self.states = {1: "Welcome!", 2: "Main Menu"}
        self.options = {1: {1: "Signup", 2: "Login", 3: "Exit"},
                        2: {1: "Find Online Users", 2: "Search User", 3: "Start a Chat", 4: "Logout"}}

        # log file initialization
        logging.basicConfig(filename="logs/peer.log", level=logging.INFO)
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
            # asks for the port number for server's tcp socket, will be needed in late phases
            peer_server_port = int(input("Enter a port number for peer server: "))

            status = self.login(username, password, peer_server_port)
            # is user logs in successfully, peer variables are set
            if status == 1:
                self.isOnline = True
                self.loginCredentials = (username, password)
                # hello message is sent to registry
                self.sendKeepAliveMessage(self.loginCredentials[0])
                self.state = 2

        elif selection == "Logout":
            # User is logged out and peer variables are set, and server and client sockets are closed
            if self.isOnline:
                self.logout(1)
                self.isOnline = False
                self.loginCredentials = (None, None)
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

        elif selection == "Start a Chat":
            print(Fore.RED + "Not available in this phase")

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
            if option == "DETAILED":
                print(Fore.RESET + "#  Username".ljust(18) + "(IP:Port)")
                for i in range(0, len(response), 2):
                    print(Fore.GREEN + f"{i+1}  {response[i]:15}{response[i+1]}")
            else:
                print(Fore.RESET + "Username")
                for username in response:
                    print(Fore.GREEN + username)
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
        if status_code == 200:
            print(Fore.GREEN + "Connected to the registry...")


# peer is started
main = peerClient()
