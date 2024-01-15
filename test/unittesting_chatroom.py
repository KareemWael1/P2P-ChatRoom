import unittest
from unittest import mock
from peer import peerMain




class TestChatroom(unittest.TestCase):


    def setUp(self):
        # Mock the input function to simulate user input during tests


        self.peer_main = peerMain()
        self.peer_instance = self.peer_main



    def test_01_create_new_user(self):
        username = "test_user260"
        password = "1234"
        result = self.peer_instance.createAccount(username, password)
        self.assertTrue(result)

    def test_02_login(self):
        username = "test_user260"
        password = "1234"
        peerServerPort = "512"
        result = self.peer_instance.login(username, password,peerServerPort)
        self.peer_instance.isOnline = True
        self.peer_instance.sendKeepAliveMessage(username)
        self.assertTrue(result)


    @mock.patch('builtins.input', side_effect=['q'])
    def test_03_createChatroom(self,mock_input):
        room_name = "testing_room25"
        username = "test_user260"
        password = "1234"
        self.peer_instance.loginCredentials = (username, password)
        result = self.peer_instance.createChatroom(room_name)
        self.assertTrue(result)

    def test_04_joinChatroom(self):
        room_name = "testing_room"
        username = "test_user260"
        password = "1234"

        self.peer_instance.loginCredentials = (username, password)
        result = self.peer_instance.joinChatroom(room_name)
        self.assertTrue(result)

    def test_05_exitChatroom(self):
        room_name = "testing_room"
        username = "test_user260"
        password = "1234"

        self.peer_instance.loginCredentials = (username, password)
        self.peer_instance.chatroom = room_name
        result = self.peer_instance.exitChatroom(username)
        self.assertTrue(result)


    def test_06_logout(self):
        option = 2
        username = "test_user260"
        password = "1234"

        self.peer_instance.loginCredentials = (username, password)
        result = self.peer_instance.logout(option)
        self.peer_instance.isOnline = False

        self.assertTrue(result)

if __name__ == '_main_':

  unittest.main()