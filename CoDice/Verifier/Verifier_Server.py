import socket
import sys
import os

HOST = '127.0.0.1'  
PORT = 65432        
BUFFER_SIZE = 4096

def read_header(conn):
    header_bytes = b""
    while b"\n" not in header_bytes:
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed before header was received")
        header_bytes += chunk
    return header_bytes.decode().strip()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}...")

        for i in range(6):
            conn, addr = s.accept()
            with conn:
                print(f"[+] Connected by {addr}")

                try:
                    header = read_header(conn)
                    filename, filesize = header.split(":", 1)
                    filename = os.path.basename(filename)
                    filesize = int(filesize)
                    print(f"[>] Receiving file: {filename} ({filesize} bytes)")
                    # Step 2: Send ACK
                    conn.sendall(b"ACK")

                    with open(filename, "wb") as f:
                        bytes_received = 0
                        while bytes_received < filesize:
                            data = conn.recv(min(4096, filesize - bytes_received))
                            if not data:
                                break
                            f.write(data)
                            bytes_received += len(data)

                    print(f"[+] File received: {filename}")
                except Exception as e:
                    print(f"[!] Error during file reception: {e}")

if __name__ == "__main__":
    start_server()