# RFMP client (Remote File Management Protocol)
# CSEC-201 socket project

import socket

# Address and port of the RFMP server (localhost for testing)
HOST = "127.0.0.1"
PORT = 8080


def connect():
    """Create a TCP socket and connect it to the server."""
    # AF_INET = IPv4, SOCK_STREAM = TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s


if __name__ == "__main__":
    sock = connect()
    print("Connected to server")
    # Always release the connection when done
    sock.close()