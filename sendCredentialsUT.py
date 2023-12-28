import unittest
from unittest.mock import MagicMock

class MyTestCase(unittest.TestCase):
    def test_send_credentials(self):

        mySendCredObj = peerMain()
        mySendCredObj.registryName = "registry.com"
        mySendCredObj.registryPort = 1234
        mySendCredObj.tcpClientSocket = MagicMock()
        expected_message = "Received from " + mySendCredObj.registryName
        expected_response = mySendCredObj.tcpClientSocket.recv(1024).decode()

        # return the expected values
        mySendCredObj.tcpClientSocket.recv.return_value.decode.return_value = expected_response

        # Call the method
        result = mySendCredObj.send_credentials(expected_message)
        mySendCredObj.tcpClientSocket.send.assert_called_once_with(expected_message.encode())
        mySendCredObj.tcpClientSocket.recv.assert_called_once_with(1024)
        self.assertEqual(result, expected_response.split())


if __name__ == '__main__':
    unittest.main()
