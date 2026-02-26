# Snake

A Command and Control framework developed for cybersecurity research and educational purposes.
This project demonstrates secure encrypted communications between a C2 server and remote clients,
implementing modern cryptographic standards including Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
key exchange and AES-GCM authenticated encryption.

---

## Architecture

The project consists of two components:

- **server.py** — The C2/C&C server, handling incoming agent connections, key exchange, session management and operator interaction.
- **agent.py** — The remote agent, deployed on the target machine, establishing an encrypted reverse shell back to the server.

---

## Cryptographic Design

### ECDHE Key Exchange (Elliptic Curve Diffie-Hellman Ephemeral)

The communication channel between the server and the agent is secured using ECDHE over the
SECP384R1 curve (384-bit, NIST P-384). The key exchange proceeds as follows:

1. The server generates an ephemeral ECDH key pair and sends its public key alongside a random nonce to the agent.
2. The agent generates its own ephemeral ECDH key pair and sends its public key back to the server.
3. Both parties independently compute the same shared secret using ECDH.
4. The shared secret is passed through HKDF (HMAC-based Key Derivation Function) with SHA-256
   to derive a 256-bit AES-GCM session key.

All key pairs are ephemeral — they are generated fresh for each connection and never stored or reused.

### Forward Secrecy (FS)

A critical property of this implementation is **Perfect Forward Secrecy (PFS)**.

Because ECDHE generates a new key pair for every session, the session keys are never derived
from any long-term static key. This means that even if an attacker were to compromise the server
or client at a later point in time and obtain all stored data, they would be **unable to decrypt
previously captured network traffic**. Each session key exists only in memory for the duration
of the session and is discarded afterward.

This is in direct contrast to static key exchange schemes (such as RSA key encryption without
ephemeral keys), where compromising the private key at any point retroactively breaks the
confidentiality of all past communications.


### AES-GCM Authenticated Encryption

Once the session key is established, all subsequent communication is encrypted using AES-256-GCM
(Galois/Counter Mode). AES-GCM provides both:

- **Confidentiality** — the data is encrypted and unreadable without the session key.
- **Integrity and authenticity** — GCM includes a 128-bit authentication tag that detects
  any tampering or corruption of the ciphertext.

Each message uses a unique 96-bit random nonce generated with `os.urandom(12)`, prepended to
the ciphertext. Nonce uniqueness is guaranteed per message, eliminating nonce-reuse vulnerabilities.

---

## Server Features (server.py)

### Session Management

- Accepts multiple incoming agent connections concurrently.
- Maintains a session registry (`sessions` dictionary) storing, per agent IP, the derived AES-GCM
  session key and the persistent TCP connection object.
- Handles agent reconnections gracefully: on reconnection, the old session data is discarded and
  a new ECDHE key exchange is performed, generating a fresh session key.

### Database Persistence

- Uses SQLite (`ddb.db`) to persist session information across server restarts.
- Tables: `sessions` (ip, keys, os, hostname, network), `logs`, `infos`.
- Uses `INSERT OR REPLACE` to handle agent reconnections without duplicating entries.


### Operator Interface

An interactive CLI exposes the following commands:

| Command   | Description                                      |
|-----------|--------------------------------------------------|
| `help`    | Display the help menu                            |
| `list`    | List all hosts registered in the database        |
| `session` | Open an interactive encrypted shell with a host  |
| `delete`  | Remove a host entry from the database            |
| `https`   | Start a local HTTPS file server (SSL)            |
| `exit`    | Shut down the server                             |


### Encrypted Shell Session

When the operator opens a session with a connected client:

- A dedicated reception thread continuously reads and decrypts incoming shell output,
  printing it to the operator's terminal in real time.
- The main thread accepts operator input and sends it encrypted to the client's shell stdin.
- The protocol uses a 4-byte big-endian length prefix before each encrypted message to handle
  TCP stream fragmentation correctly.

### HTTPS File Server

An optional HTTPS server (`HTTPS_SRV`) can be started on localhost:4443 to serve files
over TLS, useful for payload staging during authorized engagements.


<img width="938" height="778" alt="server_snake" src="https://github.com/user-attachments/assets/b08e2c60-ca0e-4a4b-8452-68a74d227869" />


---

## Client Features (client.py)

### Encrypted Reverse Shell

The client connects to the server, completes the ECDHE key exchange, and spawns a `/bin/sh`
shell process. Two threads handle bidirectional communication:

- **sender** — reads shell stdout using `os.read()` (non-blocking, low-level), encrypts the
  output with AES-GCM, and sends it to the server.
- **receiver** — receives encrypted commands from the server, decrypts them, and writes them
  to the shell's stdin.

`stdbuf -o0 -e0` is used to disable output buffering on the shell process, ensuring that
command output is transmitted to the server immediately without delay.


### Persistence via Cronjob

The agent includes a `install_cronjob()` function that installs a system crontab entry
to relaunch the agent automatically every 2 hours:
```
0 */2 * * * /path/to/python /path/to/agent.py
```

The function:
- Reads the existing crontab using `crontab -l`.
- Checks for an existing entry to avoid duplicates.
- Appends the new entry and writes it back using `crontab -`.
- Uses `sys.argv[0]` and `sys.executable` to resolve the correct paths dynamically,
  regardless of where the agent is deployed.
  
<img width="938" height="123" alt="client_snake" src="https://github.com/user-attachments/assets/235e5a67-1e11-4e05-9ab7-5ebdd49a84e9" />



### Reliability

- `recv_exact()` ensures complete message reception over TCP, looping until exactly the
  expected number of bytes is received, preventing partial-read errors due to packet fragmentation.
- A shared `threading.Event` (`stop_event`) coordinates the sender and receiver threads:
  if either thread encounters an error or the connection drops, the event is set and both
  threads terminate cleanly, after which the shell process is terminated.


---

## Requirements

Install with:
```bash
pip install -r requirements.txt
```

---

## Usage

### Server
```bash
python server.py
```

### Agent
```bash
python agent.py
```

---

## DISCLAIMER

This project is developed **strictly for educational and research purposes**.

It is intended to be used exclusively in **controlled, isolated environments** such as
dedicated cybersecurity labs, virtual machines, or sandboxed networks, and only on systems
for which the operator has **explicit written authorization**.

Deploying, executing, or distributing this software against systems without prior authorization
is **illegal** under computer fraud and cybercrime laws in most jurisdictions, including but
not limited to the Computer Fraud and Abuse Act (CFAA, United States), the Computer Misuse
Act (United Kingdom), and equivalent legislation worldwide.

The author assumes **no responsibility** for any misuse, damage, or legal consequences
resulting from the use of this software outside of authorized research contexts.

**Use responsibly. Hack ethically.**
