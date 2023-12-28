import unittest
from unittest.mock import MagicMock


class MyTestCase(unittest.TestCase):
    def test_search_user(self):
        # Create an instance of the class
        mySearchUserObj = peerMain()

        # Set up mock objects for testing
        mySearchUserObj.registryName = "registry.com"
        mySearchUserObj.registryPort = 1234
        mySearchUserObj.tcpClientSocket = MagicMock()
        username = "testuser"
        expected_response = username + " is not found"
        mySearchUserObj.tcpClientSocket.recv.return_value.decode.return_value = "SEARCH_USER " + username + " " + expected_response

        # Call the method under test
        result = mySearchUserObj.search_user(username)
        mySearchUserObj.tcpClientSocket.send.assert_called_once_with(("SEARCH_USER " + username).encode())
        mySearchUserObj.tcpClientSocket.recv.assert_called_once_with(1024)
        self.assertEqual(result, expected_response)


if __name__ == '__main__':
    unittest.main()
