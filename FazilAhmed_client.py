# RFMP client (Remote File Management Protocol)
# CSEC-201 socket project

import socket
import secrets
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

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


def generate_rsa_keys():
    """Generate the client's RSA key pair and return (private, public)."""
    # 2048 bits is the standard minimum size for RSA today
    private_key = RSA.generate(2048)

    # The public key is derived from the private key and can be shared
    public_key = private_key.publickey()
    return private_key, public_key


def generate_session_key(algorithm):
    """Create a random session key for the chosen algorithm."""
    if algorithm == "AES":
        # AES-128 uses a 16 byte key from a secure random source
        return get_random_bytes(16)
    elif algorithm == "Caesar":
        # Caesar uses a shift from 1 to 25 (0 would change nothing)
        return secrets.randbelow(25) + 1
    else:
        raise ValueError("Unknown algorithm: " + algorithm)


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

    # Generate the client key pair and show the start of the public key
    private_key, public_key = generate_rsa_keys()
    print("Client public key starts with:", public_key.export_key().decode()[:30])

    # Generate one session key for each algorithm to check they work
    print("AES session key:", generate_session_key("AES").hex())
    print("Caesar session key:", generate_session_key("Caesar"))

    # Always release the connection when done
    sock.close()