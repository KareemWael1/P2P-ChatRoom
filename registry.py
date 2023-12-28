"""
    ## Credits for the starting code
    ##  150114822 - Eren Ulaş
"""

from socket import *
import threading
import select
import logging

from colorama import Fore

import db
import ssl


# This class is used to process the peer messages sent to registry
# for each peer connected to registry, a new client thread is created
class ClientThread(threading.Thread):
    # initializations for client thread
    def __init__(self, ip, port, tcpClientSocket):
        threading.Thread.__init__(self)
        # ip of the connected peer

        self.ip = ip
        # port number of the connected peer
        self.port = port
        # socket of the peer
        self.tcpClientSocket = tcpClientSocket
        # Create SSL context
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile="security/server.crt", keyfile="security/server.key")
        # username, online status and udp server initializations
        self.username = None
        self.isOnline = True
        self.udpServer = None
        print("New thread started for " + ip + ":" + str(port))

    # main of the thread
    def run(self):
        # locks for thread which will be used for thread synchronization
        self.lock = threading.Lock()
        print(Fore.BLUE + "Connection from: " + self.ip + ":" + str(port))
        print(Fore.BLUE + "IP Connected: " + self.ip)

        while True:
            try:
                # waits for incoming messages from peers
                message = self.tcpClientSocket.recv(1024).decode().split()
                logging.info("Received from " + self.ip + ":" + str(self.port) + " -> " + " ".join(message))
                #   JOIN    #
                if message[0] == "REGISTER":
                    # join-exist is sent to peer,
                    # if an account with this username already exists
                    if db.is_account_exist(message[1]):
                        response = "REGISTER <EXIST> <300>"
                        print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # join-success is sent to peer,
                    # if an account with this username is not exist, and the account is created
                    else:
                        db.register(message[1], message[2])
                        response = "REGISTER <SUCCESS> <200>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                #   LOGIN    #
                elif message[0] == "LOGIN":
                    # login-account-not-exist is sent to peer,
                    # if an account with the username does not exist
                    if not db.is_account_exist(message[1]):
                        response = "AUTH <FAILURE> <404>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-online is sent to peer,
                    # if an account with the username already online
                    elif db.is_account_online(message[1]):
                        response = "AUTH <ONLINE> <300>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    # login-success is sent to peer,
                    # if an account with the username exists and not online
                    else:
                        # retrieves the account's password, and checks if the one entered by the user is correct
                        retrieved_pass = db.get_password(message[1])
                        # if password is correct, then peer's thread is added to threads list
                        # peer is added to db with its username, port number, and ip address
                        if retrieved_pass == message[2]:
                            self.username = message[1]
                            self.lock.acquire()
                            try:
                                tcpThreads[self.username] = self
                            finally:
                                self.lock.release()

                            db.user_login(message[1], self.ip, self.port)
                            # login-success is sent to peer,
                            # and a UDP server thread is created for this peer, and thread is started
                            # timer thread of the udp server is started
                            response = "AUTH <SUCCESS> <200>"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                            self.udpServer = UDPServer(self.username, self.tcpClientSocket)
                            self.udpServer.start()
                            self.udpServer.timer.start()
                        # if password not matches and then login-wrong-password response is sent
                        else:
                            response = "AUTH <FAILURE> <404>"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                #   LOGOUT  #
                elif message[0] == "LOGOUT":
                    # if user is online, removes the user from onlinePeers list and removes the thread for this user
                    # from tcpThreads socket is closed and timer thread of the udp for this user is cancelled
                    if db.is_account_online(self.username):
                        db.user_logout(message[1])
                        self.lock.acquire()
                        try:
                            if self.username in tcpThreads:
                                del tcpThreads[self.username]
                        finally:
                            self.lock.release()
                        print(Fore.BLUE + self.ip + ":" + str(self.port) + " is logged out")
                        self.tcpClientSocket.close()
                        self.udpServer.timer.cancel()
                        break
                    else:
                        self.tcpClientSocket.close()
                        break

                #   SEARCH  #
                elif message[0] == "SEARCH_USER":
                    # checks if an account with the username exists
                    if db.is_account_exist(message[1]):
                        # checks if the account is online
                        # and sends the related response to peer
                        if db.is_account_online(message[1]):
                            peer_info = db.get_peer_ip_port(message[1])
                            response = "SEARCH_USER_RESPONSE <SUCCESS> <200> " + str(peer_info[0]) + ":" + str(
                                peer_info[1])
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        else:
                            response = "SEARCH_USER_RESPONSE <NOT_ONLINE> <300>"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                    # enters if username does not exist
                    else:
                        response = "SEARCH_USER_RESPONSE <NOT_FOUND> <404>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                # online peers discovery
                elif message[0] == "DISCOVER_PEERS":
                    peer_list = db.get_online_peer_list()
                    # remove the requesting user from the list
                    if peer_list:
                        for peer in peer_list:
                            if peer['username'] == message[2]:
                                peer_list.remove(peer)
                    if peer_list and len(peer_list) > 0:
                        # detailed list
                        if message[1] == "DETAILED":
                            response = "PEER_LIST <SUCCESS> <200> " + ' '.join(
                                f"{peer['username']} ({peer['ip']}:{peer['port']})" for peer in peer_list
                            )

                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        # partial list
                        else:
                            usernames = [peer['username'] for peer in peer_list]
                            response = "PEER_LIST <SUCCESS> <200> " + ' '.join(usernames)
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                    # failure empty list
                    else:
                        response = "PEER_LIST <FAILURE> <404>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                elif message[0] == "CREATE-CHAT-ROOM":
                        # CREATE-exist is sent to peer,
                        # if a room with this username already exists
                        if db.is_room_exist(message[1]):
                            response = "CREATION <FAILURE> <404>"
                            print("From-> " + self.ip + ":" + str(self.port) + " " + response)
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())
                        else:
                            db.add_chat_room(message[1],message[2])
                            response = "CREATION <SUCCESS> <200>"
                            logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                            self.tcpClientSocket.send(response.encode())

                elif message[0] == "ROOM-EXIT":
                    if db.is_room_exist(message[2]):
                        db.remove_peer_from_chatroom(message[1], message[2])
                        response = "ROOM-EXIT-RESPONSE <SUCCESS> <200>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)

                        self.tcpClientSocket.send(response.encode())
                    else :
                        response = "ROOM-EXIT-RESPONSE <FAILURE> <404>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)

                        self.tcpClientSocket.send(response.encode())

                elif message[0] == "JOIN-CHAT-ROOM":
                    # checks if an account with the username exists
                    if db.is_room_exist(message[1]):
                        # checks if the room exists
                        # and sends the related response to peer
                        peers = db.get_chatroom_peers(message[1])
                        peers.append(message[2])
                        peers = list(set(peers))
                        db.update_chatroom(message[1], peers)
                        response = "JOIN <SUCCESS> <200>"

                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())
                    else:
                        response = "JOIN <FAILURE> <404>"
                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)
                        self.tcpClientSocket.send(response.encode())

                    # enters if username does not exist


                elif message[0] == "SHOW-ROOM-LIST":

                    # checks if an account with the username exists

                    chat_rooms_list = db.get_chat_rooms_list()

                    if chat_rooms_list is not None:

                        response = "ROOMS-LIST <SUCCESS> <200> " + ' '.join(

                            f" {chatroom['name']} : {chatroom['peers']} ,)" for chatroom in chat_rooms_list

                        )

                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)

                        self.tcpClientSocket.send(response.encode())

                    else:

                        response = "ROOM-LIST <FAILURE> <404>"

                        logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)

                        self.tcpClientSocket.send(response.encode())






            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
                response = "HELLO_BACK " + "FAILURE " + "404"
                logging.info("Send to " + self.ip + ":" + str(self.port) + " -> " + response)

                db.user_logout(self.username)

                # function for resetting the timeout for the udp timer thread

    def resetTimeout(self):
        self.udpServer.resetTimer()


# implementation of the udp server thread for clients
class UDPServer(threading.Thread):

    # udp server thread initializations
    def __init__(self, username, clientSocket):
        threading.Thread.__init__(self)
        self.username = username
        self.default_timeout = 3
        # timer thread for the udp server is initialized
        self.timer = threading.Timer(self.default_timeout, self.waitKeepAliveMessage)
        self.tcpClientSocket = clientSocket

    # if hello message is not received before timeout
    # then peer is disconnected
    def waitKeepAliveMessage(self):

        if self.username is not None:
            notification = "TIMEOUT " + self.username
            self.tcpClientSocket.send(notification.encode())
            db.user_logout(self.username)
            if self.username in tcpThreads:
                del tcpThreads[self.username]
        self.tcpClientSocket.close()
        print(Fore.BLUE + "Removed " + self.username + " from online peers")

    # resets the timer for udp server
    def resetTimer(self):
        self.timer.cancel()
        self.timer = threading.Timer(self.default_timeout, self.waitKeepAliveMessage)
        self.timer.start()


# tcp and udp server port initializations
print("Registry started...")
port = 15600
portUDP = 15500

# db initialization
db = db.DB()

# gets the ip address of this peer
# first checks to get it for Windows devices
# if the device that runs this application is not windows
# it checks to get it for macOS devices
hostname = gethostname()
try:
    host = gethostbyname(hostname)
except gaierror:
    import netifaces as ni

    host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

print("Registry IP address: " + host)
print("Registry port number: " + str(port))

# onlinePeers list for online account
onlinePeers = {}
# accounts list for accounts
accounts = {}
# tcpThreads list for online client's thread
tcpThreads = {}

# tcp and udp socket initializations
tcpSocket = socket(AF_INET, SOCK_STREAM)
udpSocket = socket(AF_INET, SOCK_DGRAM)
tcpSocket.bind((host, port))
udpSocket.bind((host, portUDP))
tcpSocket.listen(1000)

# input sockets that are listened
inputs = [tcpSocket, udpSocket]

# log file initialization
logging.basicConfig(filename="logs/registry.log", level=logging.INFO)

# as long as at least a socket exists to listen registry runs
while inputs:

    print("Listening for incoming connections...")
    # monitors for the incoming connections
    readable, writable, exceptional = select.select(inputs, [], [])
    for s in readable:
        # if the message received comes to the tcp socket
        # the connection is accepted and a thread is created for it, and that thread is started
        if s is tcpSocket:
            tcpClientSocket, addr = tcpSocket.accept()
            newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
            newThread.tcpClientSocket = newThread.context.wrap_socket(newThread.tcpClientSocket, server_side=True)
            newThread.start()
            response = "HELLO_BACK " + "SUCCESS " + "200 "
            logging.info("Send to " + addr[0] + ":" + str(addr[1]) + " -> " + response)
            newThread.tcpClientSocket.send(response.encode())
        # if the message received comes to the udp socket
        elif s is udpSocket:
            # received the incoming udp message and parses it
            message, clientAddress = s.recvfrom(1024)
            message = message.decode().split()
            # checks if it is a hello message
            if message[0] == "KEEP_ALIVE":
                # checks if the account that this hello message
                # is sent from is online
                if message[1] in tcpThreads:
                    # resets the timeout for that peer since the hello message is received
                    tcpThreads[message[1]].resetTimeout()
                    print("KEEP_ALIVE is received from " + message[1])
                    logging_message = "KEEP_ALIVE <SUCCESS> <200>"

                    logging.info(
                        "Received from " + clientAddress[0] + ":" + str(clientAddress[1]) + " -> " + " ".join(message))
                    # Send the response back to the UDP client

# registry tcp socket is closed
tcpSocket.close()
