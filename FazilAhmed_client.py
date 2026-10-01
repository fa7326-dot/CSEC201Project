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


def parse_packet(text):
    """Split a packet like (CC,key) into a list of its fields."""
    # Remove surrounding whitespace, then the opening and closing brackets
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]

    # Split on commas and trim any spaces around each field
    return [field.strip() for field in text.split(",")]


def send_start(sock, secure):
    """Send the Start packet (SS) and return the server's reply."""
    # The last field is 1 if secured communication is required, otherwise 0
    flag = "1" if secure else "0"
    packet = "(SS,RFMP,v1.0," + flag + ")"
    sock.send(packet.encode())

    # Wait for the Confirm-Connection packet (CC) from the server
    reply = sock.recv(1024).decode()
    return reply


if __name__ == "__main__":
    sock = connect()
    print("Connected to server")
    reply = send_start(sock, False)
    print("Server replied:", reply)
    print("Parsed fields:", parse_packet(reply))
    # Always release the connection when done
    sock.close()