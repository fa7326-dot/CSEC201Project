# RFMP client (Remote File Management Protocol)
# CSEC-201 socket project

import socket
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Address and port of the RFMP server (localhost for testing)
HOST = "127.0.0.1"
PORT = 8080

# Username sent to the server inside the Encryption packet
USERNAME = "nirvan"


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


def encrypt_session_key(session_key, server_public_key):
    """Encrypt the session key with the server's RSA public key."""
    # The Caesar key is a number, so turn it into bytes before encrypting
    if isinstance(session_key, int):
        data = str(session_key).encode()
    else:
        data = session_key

    # OAEP is the recommended padding scheme for RSA encryption
    cipher = PKCS1_OAEP.new(server_public_key)
    return cipher.encrypt(data)


def send_start(sock, secure):
    """Send the Start packet (SS) and return the server's reply."""
    # The last field is 1 if secured communication is required, otherwise 0
    flag = "1" if secure else "0"
    packet = "(SS,RFMP,v1.0," + flag + ")"
    sock.send(packet.encode())

    # Wait for the Confirm-Connection packet (CC) from the server
    reply = sock.recv(4096).decode()
    return reply


def secure_setup(sock, algorithm, username):
    """Run the secured setup phase and return (session_key, private_key)."""
    # Ask for secured communication and read the CC packet with the server key
    reply = send_start(sock, True)
    fields = parse_packet(reply)
    if fields[0] != "CC" or len(fields) < 2:
        raise ValueError("Unexpected reply from server: " + reply)
    server_public_key = RSA.import_key(fields[1])

    # Prepare the client's keys and encrypt the session key for the server
    private_key, public_key = generate_rsa_keys()
    session_key = generate_session_key(algorithm)
    encrypted_key = encrypt_session_key(session_key, server_public_key)

    # Send the Encryption packet (the key is hex encoded so it fits in text)
    client_key_pem = public_key.export_key().decode()
    packet = ("(EC," + algorithm + "," + encrypted_key.hex() + ","
              + username + ":" + client_key_pem + ")")
    sock.send(packet.encode())
    return session_key, private_key


if __name__ == "__main__":
    sock = connect()
    print("Connected to server")

    # Run the secured setup phase using AES
    session_key, private_key = secure_setup(sock, "AES", USERNAME)
    print("Secure setup finished, session key (hex):", session_key.hex())

    # Always release the connection when done
    sock.close()