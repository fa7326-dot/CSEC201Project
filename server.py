"""RFMP Server - CSEC201 PROJECT 
Author: Siyaa Sathyan (UID:433004781)
"""
import socket
import threading
import subprocess
import os
import rfmp_crypto as crypto  # Import cryptography helper module

host = "0.0.0.0"
port = 9999

ERROR_CODES = {
    "E01": "Unknown or malformed packet",
    "E02": "File not found",
    "E03": "Command failed",
    "E04": "Encryption error",
}


class Client:
    """Holds the info about a connected client."""
    def __init__(self, conn, addr):
        self.conn = conn # the client socket
        self.addr = addr # the client address
        self.secure = False # this client encryption flag
        self.algorithm = None # this client chosen algorithm
        self.client_key = None # this client key
        self.open_file = None # this client open file
        self.session_key = None # decrypted session key used for symmetric cipher
        # Generate RSA keypair for this client's setup phase
        self.rsa_priv, self.rsa_pub = crypto.generate_rsa_keys()
        

def make_error(code):
    return f"(EE,{code},{ERROR_CODES.get(code,'')})" # gives the error code and message E01, E02, E03, E04

    
def handle_start(client, fields):
    """Handle the Start (SS) packet: (SS, RFMP, v1.0, 0|1)."""
    if len(fields) < 3:
        return make_error("E01")
    protocol = fields[0]
    version = fields[1]
    wants_encryption = fields[2]
    
    if protocol != "RFMP":
        return make_error("E01")
    
    if wants_encryption == "1":
        client.secure = True
        # Clean newline characters in PEM string for protocol transmission
        pub_key_clean = client.rsa_pub.replace("\n", "||")
        return f"(CC,{pub_key_clean})"
        
    return "(CC)"


def handle_encryption(client, fields):
    """Handle the Encryption (EC) packet: (EC, Algorithm, Encrypted_Session_Key, Username:Client_Public_Key)."""
    if len(fields) < 2:
        return make_error("E04")
    
    client.algorithm = fields[0]
    encrypted_session_key = fields[1]
    
    if len(fields) >= 3:
        client.client_key = fields[2]  # credentials / client public key

    try:
        # Decrypt the session key using the server's RSA private key
        client.session_key = crypto.rsa_decrypt(client.rsa_priv, encrypted_session_key)
        return "(SC)"
    except Exception:
        return make_error("E04")


def handle_prompt(cmd_text):
    """Run a shell command on the server and return its output."""
    if not cmd_text:
        return make_error("E03")
    cmd_parts = cmd_text.strip().split(maxsplit=1)
    base_cmd = cmd_parts[0]
    args = cmd_parts[1] if len(cmd_parts) > 1 else ""

    # Handle 'cd' internally to update the server session's working directory
    if base_cmd == "cd":
        try:
            target_dir = args if args else os.path.expanduser("~")
            os.chdir(target_dir)  # Change directory for the current server process
            return f"(SC,Changed directory to {os.getcwd()})"
        except Exception as e:
            return make_error("E03")
    try:
        result = subprocess.run(
            ["powershell", "-Command", cmd_text],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return f"(SC,{output.strip() or 'OK'})"
    except Exception:
        return make_error("E03")


def handle_open_write(client, filename):
    """Handle (CM, openWrite, filename) — open a file for writing."""
    if not filename:
        return make_error("E03")
    try:
        client.open_file = open(filename, "w")
        return "(SC)"
    except Exception:
        return make_error("E03")


def handle_data(client, fields):
    """Handle (DP, text) — write text to the currently open file."""
    if not client.open_file:
        return make_error("E03")
    text = fields[0] if fields else ""
    
    # Decrypt incoming text payload if session is secured
    if client.secure and client.algorithm and client.session_key:
        try:
            text = crypto.decrypt_payload(client.algorithm, text, client.session_key)
        except Exception:
            return make_error("E04")

    try:
        client.open_file.write(text)
        client.open_file.flush()
        return "(SC)"
    except Exception:
        return make_error("E03")


def handle_open_read(client, filename):
    """Handle (CM, openRead, filename) — open a file for reading."""
    if not filename:
        return make_error("E03")
    try:
        with open(filename, "r") as f:
            content = f.read()

        # Encrypt outgoing text payload if session is secured
        if client.secure and client.algorithm and client.session_key:
            try:
                content = crypto.encrypt_payload(client.algorithm, content, client.session_key)
            except Exception:
                return make_error("E04")

        return f"(DP,{content})"
    except FileNotFoundError:
        return make_error("E02")
    except Exception:
        return make_error("E03")


def handle_command(client, fields):
    """Handle a Command (CM) packet: (CM, cmd_type, args...)."""
    if not fields:
        return make_error("E01")

    cmd_type = fields[0]
    args = ", ".join(fields[1:]) if len(fields) > 1 else ""

    if cmd_type == "prompt":
        return handle_prompt(args)
    elif cmd_type == "openWrite":
        return handle_open_write(client, args)
    elif cmd_type == "openRead":
        return handle_open_read(client, args)
    return make_error("E01")

    
def handle_client(conn, addr):
    """Serve one client connection"""
    sess = Client(conn, addr)
    print(f"Connected by {addr}")

    while True:
        data = sess.conn.recv(4096)
        if not data:
            break

        raw_packet = data.decode("utf-8")  # bytes -> string
        ptype, fields = parse_packet(raw_packet)
        print(f"Client sent: {raw_packet}")

        if ptype == "SS":
            reply = handle_start(sess, fields)
        elif ptype == "EC":
            reply = handle_encryption(sess, fields)
        elif ptype == "CM":
            reply = handle_command(sess, fields)
        elif ptype == "DP":
            reply = handle_data(sess, fields)
        elif ptype == "End":
            sess.conn.sendall(b"(SC)")
            break
        else:
            reply = make_error("E01")

        sess.conn.sendall(reply.encode())
        
    if sess.open_file:
        sess.open_file.close()
    sess.conn.close()
    print(f"Disconnected:{addr}")


def main():
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port)) 
        s.listen(5)
        print(f"Server listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()  # Accept a new connection
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


def parse_packet(raw):
    # Implementation for parsing the raw packet data
    """splits "(TYPE, f1, f2)" into tuples of ("TYPE", ["f1", "f2"])"""
    
    raw = raw.strip()  # Remove leading/trailing whitespace
    if raw.startswith("(") and raw.endswith(")"):
        
        raw = raw[1:-1]  # Remove the parentheses
        
        parts = [p.strip() for p in raw.split(",", 1)]  # Split by comma and strip whitespace
        
        if not parts or not parts[0]:  # Check if the first part (TYPE) is empty
            return "", []  # Returns empty values if the packet type is missing
        
        ptype = parts[0]  # The first part is the packet type
        rest = parts[1] if len(parts) > 1 else ""  # The rest is the remaining data
        fields = [f.strip() for f in rest.split(",")] if rest else []  # Splits the rest into fields
        return ptype, fields  # Return the packet type and fields as a tuple


if __name__ == "__main__":
    main()  # Call the main function to start the server