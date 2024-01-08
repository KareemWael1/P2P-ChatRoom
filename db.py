from pymongo import MongoClient


# Includes database operations
class DB:

    # db initializations
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017/')
        self.db = self.client['p2p-chat']

    # checks if an account with the username exists
    def is_account_exist(self, username):
        cursor = self.db.accounts.find({'username': username})
        doc_count = 0

        for _ in cursor:
            doc_count += 1

        if doc_count > 0:
            return True
        else:
            return False

    # registers a user
    def register(self, username, password):
        account = {
            "username": username,
            "password": password
        }
        self.db.accounts.insert_one(account)

    # retrieves the password for a given username
    def get_password(self, username):
        return self.db.accounts.find_one({"username": username})["password"]

    # checks if an account with the username online
    def is_account_online(self, username):
        count = self.db.online_peers.count_documents({'username': username})
        return count > 0

    # logs in the user
    def user_login(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port,
            "chatroom": None
        }
        self.db.online_peers.insert_one(online_peer)

    # logs out the user
    def user_logout(self, username):
        user = self.db.online_peers.find_one({"username": username})
        if user:
            chatroom = user["chatroom"]
            if chatroom:
                self.remove_peer_from_chatroom(username, chatroom)
            self.db.online_peers.delete_one({"username": username})

    # retrieves the ip address and the port number of the username
    def get_peer_ip_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return res["ip"], res["port"]

    def get_peer_chatroom(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return res["chatroom"]

    def get_online_peer_list(self):
        online_peers_cursor = self.db.online_peers.find()
        online_peers_list = list(online_peers_cursor)
        return online_peers_list

    def add_online_peer_chatroom(self, username, room_name):
        res = self.db.online_peers.find_one({"username": username})
        self.db.online_peers.update_one(
            {"username": res["username"]},
            {
                "$set": {
                    "ip": res["ip"],
                    "port": res["port"],
                    "chatroom": room_name
                }
            }
        )

    def add_chat_room(self, name, host):
        chat_room = {
            "name": name,
            "peers": [host],
            "host": host
        }
        self.db.Chatrooms.insert_one(chat_room)

    def get_chat_rooms_list(self):
        return list(self.db.Chatrooms.find())

    def is_room_exist(self, room_name):
        count = self.db.Chatrooms.count_documents({'name': room_name})

        return count > 0

    def remove_peer_from_chatroom(self, username, room_name):
        # Find the chat room
        chat_room = self.db.Chatrooms.find_one({"name": room_name})

        # Check if the chat room exists
        if chat_room:
            # Remove the username from the list of peers
            chat_room["peers"].remove(username)

            if len(chat_room["peers"]) == 0:
                self.delete_chatroom(room_name)
                return
            if chat_room["host"] == username:
                chat_room["host"] = chat_room["peers"][0]

            # Update the database with the modified chat room
            self.db.Chatrooms.update_one(
                {"name": room_name},
                {
                    "$set": {
                        "peers": chat_room["peers"],
                        "host": chat_room["host"]
                    }
                }
            )

    def get_chatroom_peers(self, room_name):

        chat_room = self.db.Chatrooms.find_one({"name": room_name})

        if chat_room:
            return chat_room.get("peers", [])
        else:
            return []

    def get_chatroom_host(self, room_name):

        chat_room = self.db.Chatrooms.find_one({"name": room_name})

        if chat_room:
            return chat_room.get("host")
        else:
            return None

    def update_chatroom(self, room_name, peers, host):
        self.db.Chatrooms.update_one(
            {"name": room_name},
            {
                "$set": {
                    "peers": peers,
                    "host": host
                }
            }
        )

    # Deletes the chatroom
    def delete_chatroom(self, name):
        self.db.Chatrooms.delete_one({"name": name})
