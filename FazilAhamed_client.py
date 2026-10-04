# RFMP client (Remote File Management Protocol)
# CSEC-201 socket project
# Encryption is handled separately by the team (see the marked spots below)

import socket

# Address and port of the RFMP server (localhost for testing)
HOST = "127.0.0.1"
PORT = 9999

# Menu choice mapped to (label, packet kind, command, argument prompt)
# A prompt of None means the command needs no argument
COMMANDS = {
    "1": ("mkdir (create a folder)", "prompt", "mkdir", "Folder name: "),
    "2": ("cd (change directory)", "prompt", "cd", "Directory path: "),
    "3": ("rmdir (delete a folder)", "prompt", "rmdir", "Folder name: "),
    "4": ("del (delete a file)", "prompt", "del", "File name: "),
    "5": ("ren (rename a folder)", "prompt", "ren",
          "Old name and new name (separated by a space): "),
    "6": ("openRead (read a server file)", "openRead", None,
          "File name to read: "),
    "7": ("openWrite (write a server file)", "openWrite", None,
          "File name to write: "),
    "8": ("whoami (current user)", "prompt", "whoami", None),
    "9": ("hostname (server name)", "prompt", "hostname", None),
    "10": ("echo (print text)", "prompt", "echo", "Text to echo: "),
    "11": ("ls (list files)", "prompt", "ls", None),
    "12": ("pwd (current folder)", "prompt", "pwd", None),
}


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


def receive(sock):
    """Read one reply from the server and return it as text."""
    reply = sock.recv(65536).decode()

    # An empty read means the server closed the connection
    if not reply:
        raise ConnectionError("Server closed the connection")
    return reply


def send_start(sock):
    """Send the Start packet (SS) and check the Confirm packet (CC)."""
    # The last field is 0 because secured communication is not used here
    # ENCRYPTION HOOK: the secured setup (flag 1 and the EC packet) goes here
    sock.send("(SS,RFMP,v1.0,0)".encode())

    reply = receive(sock)
    if parse_packet(reply)[0] != "CC":
        raise ValueError("Unexpected reply from server: " + reply)


def send_command(sock, command_type, argument):
    """Send a command packet (CM) and return the server's reply."""
    # Examples: (CM,prompt,mkdir folder1) and (CM,openRead,data.txt)
    packet = "(CM," + command_type + "," + argument + ")"
    sock.send(packet.encode())
    return receive(sock)


def handle_response(reply):
    """Show the server's SC (success) or EE (error) reply to the user."""
    fields = parse_packet(reply)
    if fields[0] == "SC":
        print("Success")
        # Anything after SC is output from the server, so show it
        if len(fields) > 1:
            print(",".join(fields[1:]))
    elif fields[0] == "EE":
        # Exception packet: (EE, error code, description)
        code = fields[1] if len(fields) > 1 else "?"
        description = ",".join(fields[2:])
        print("Error", code + ":", description)
    else:
        print("Unexpected reply:", reply)


def open_read(sock, filename):
    """Ask the server for a file's contents and display them."""
    reply = send_command(sock, "openRead", filename)

    # An EE packet means the file could not be read
    if reply.strip().startswith("(EE"):
        handle_response(reply)
    else:
        # ENCRYPTION HOOK: decrypt the contents here when secured
        print("File contents:")
        print(reply)


def open_write(sock, filename):
    """Create a file on the server and send its text in a Data packet."""
    reply = send_command(sock, "openWrite", filename)
    handle_response(reply)

    # Only send data if the server agreed to open the file
    if not reply.strip().startswith("(SC"):
        return

    text = input("Text to write: ")

    # ENCRYPTION HOOK: encrypt the text here when secured
    sock.send(("(DP," + text + ")").encode())
    handle_response(receive(sock))


def show_menu():
    """Print the list of options the user can choose from."""
    print()
    for key, entry in COMMANDS.items():
        print(key + ". " + entry[0])
    print("0. Exit")


def command_loop(sock):
    """Repeat the menu until the user chooses to exit."""
    while True:
        show_menu()
        choice = input("Choose an option: ").strip()

        if choice == "0":
            break

        if choice not in COMMANDS:
            print("Invalid option")
            continue

        label, kind, command, prompt = COMMANDS[choice]

        # Ask for the argument only if the command needs one
        argument = input(prompt).strip() if prompt else ""

        if kind == "openRead":
            open_read(sock, argument)
        elif kind == "openWrite":
            open_write(sock, argument)
        else:
            # Prompt commands send the full command text as the argument
            full_command = (command + " " + argument).strip()
            handle_response(send_command(sock, "prompt", full_command))


def close_connection(sock):
    """Send the End packet so the server knows the client has finished."""
    sock.send("(End)".encode())
    sock.close()


if __name__ == "__main__":
    try:
        sock = connect()
    except ConnectionRefusedError:
        print("Could not connect, check that the server is running")
        raise SystemExit(1)
    print("Connected to server")

    try:
        # Setup phase, then the operation phase
        send_start(sock)
        print("Connection confirmed")
        command_loop(sock)
    except ConnectionError as error:
        print("Connection lost:", error)

    # Closing phase
    close_connection(sock)
    