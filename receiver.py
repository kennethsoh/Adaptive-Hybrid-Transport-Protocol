from GameNetAPI import GameNetAPI, Packet

# Constants
HOST = "127.0.0.1"
PORT = 5000
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

def on_message_received(packet: Packet, addr: tuple):
    try:
        message = packet.payload.decode('utf-8')
        print(f"Received message from {addr}: {message}\n")
    except UnicodeDecodeError:
        print(f"Received: Non-UTF8 message of length {len(packet.payload)} from {addr}\n")

def main():
    print("Starting GameNet Receiver...")
    try:
        # Check for Certificates & Keys File
        with open(CERT_FILE, 'r') as cert_file, open(KEY_FILE, 'r') as key_file:
            pass
    except FileNotFoundError:
        print("Certificate or Key file not found. Generating Files.")
        GameNetAPI.generate_self_signed_cert()
    
    # Initialize GameNetAPI
    api = GameNetAPI(is_server=True, host=HOST, port=PORT)
    api.set_deliver_callback(on_message_received)

    try:
        api.start_server(CERT_FILE, KEY_FILE)
        print(f"Server started on {HOST}:{PORT}. Waiting for messages...\n")
        api.listen_for_incoming()
    except KeyboardInterrupt:
        print("Shutting Down Server (Ctrl+C pressed)...")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("--- Final Metrics ---\n")
        api.report_results()
        api.close()
        print("Server closed. Exiting.")

if __name__ == "__main__":
    main()
