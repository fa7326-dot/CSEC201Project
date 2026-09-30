"""RFMP Server - CSEC201 PROJECT 
Author: Siyaa Sathyan (UID:433004781)
"""

host = "0.0.0.0"
port = 9999

def main():
    #the below shows startup message for the server; f string inserts the host and port values into the string
    print(f"Starting RFMP server on {host}:{port}")
    

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