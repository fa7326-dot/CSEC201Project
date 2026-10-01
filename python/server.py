"""RFMP Server - CSEC201 PROJECT 
Author: Siyaa Sathyan (UID:433004781)
"""
import socket
host = "0.0.0.0"
port = 9999

def main():
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port)) 
        s.listen(5)
        print(f"Server listening on {host}:{port}")
        
        while True:
            conn, addr = s.accept()  # Accept a new connection
            print(f"Connected by {addr}")
            data = conn.recv(2024)  # Receive data from the client
            if not data:
                conn.close()
                continue
            raw_packet = data.decode('utf-8')  # Decode the received bytes to string
            ptype, fields = parse_packet(raw_packet)  # Parse the packet
            print(f"Client sent: {raw_packet}")
                
            print(f"Parse: type={ptype}, fields={fields}") #

            conn.close()
    

def parse_packet(raw):
    # Implementation for parsing the raw packet data
    """splits "(TYPE, f1, f2)" into tuples of ("TYPE", ["f1", "f2"])"""
    
    raw = raw.strip()  # Remove leading/trailing whitespace
    if raw.startswith("(") and raw.endswith(")"):
        
        raw = raw[1:-1]  # Remove the parentheses
        
        parts = [p.strip() for p in raw.split(",", 1)]  # Split by comma and strip whitespace
        
        if not parts or not parts[0]:  # Check if the first part (TYPE) is empty
            return "",[]  # Returns empty values if the packet type is missing
        
        ptype = parts[0]  # The first part is the packet type
        rest = parts[1] if len(parts) > 1 else ""  # The rest is the remaining data
        fields = [f.strip() for f in rest.split(",")] if rest else []  # Splits the rest into fields
        return ptype, fields  # Return the packet type and fields as a tuple

if __name__ == "__main__":
    main()  # Call the main function to start the server