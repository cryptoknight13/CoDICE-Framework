import socket
import sys
import os

HOST = '127.0.0.1'
PORT = 65432
BUFFER_SIZE = 4096

def send_files(file_paths):
    for file_path in file_paths:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            filesize = os.path.getsize(file_path)
            filename = os.path.basename(file_path)

            header = f"{filename}:{filesize}\n"
            s.sendall(header.encode())

            ack = s.recv(3)
            if ack != b"ACK":
                print("[!] Did not receive ACK from server. Aborting.")
                return

            with open(file_path, "rb") as f:
                s.sendfile(f)

            print(f"[+] File '{filename}' sent successfully.")

if __name__ == "__main__":
    send_files(sys.argv[1:])