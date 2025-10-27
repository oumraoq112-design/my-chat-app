#!/usr/bin/env python3
import socket
import threading
import json
import base64
import os
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000

def recv_json(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
        if b"\n" in chunk:
            break
    try:
        return json.loads(data.decode('utf-8').strip())
    except:
        return None

def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode('utf-8'))

def save_pem(private_key, public_key, username):
    with open(f"{username}_private_key.pem", "wb") as f:
        f.write(private_key.export_key('PEM'))
    with open(f"{username}_public_key.pem", "wb") as f:
        f.write(public_key.export_key('PEM'))

def load_or_create_rsa(username, bits=2048):
    priv_file = f"{username}_private_key.pem"
    pub_file = f"{username}_public_key.pem"
    if os.path.exists(priv_file) and os.path.exists(pub_file):
        priv = RSA.import_key(open(priv_file,"rb").read())
        pub = RSA.import_key(open(pub_file,"rb").read())
        return priv, pub
    else:
        key = RSA.generate(bits)
        priv = key
        pub = key.publickey()
        save_pem(priv, pub, username)
        return priv, pub

def json_log_append(filename, entry):
    if os.path.exists(filename):
        with open(filename, "r", encoding='utf-8') as f:
            try:
                data = json.load(f)
            except:
                data = []
    else:
        data = []
    data.append(entry)
    with open(filename, "w", encoding='utf-8') as f:
        json.dump(data, f, indent=2)

class Client:
    def __init__(self, username):
        self.username = username
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.privkey, self.pubkey = load_or_create_rsa(username)
        self.session_keys = {}  # peer -> raw bytes AES key
        self.lock = threading.Lock()
        self.messages_file = f"{username}_messages.json"

    def connect(self):
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        # Register public key with server
        send_json(self.sock, {"type":"REGISTER", "username": self.username, "pubkey_pem": self.pubkey.export_key('PEM').decode('utf-8')})
        resp = recv_json(self.sock)
        if not resp or resp.get("type") != "REGISTERED":
            print("Registration failed:", resp)
            return False
        print(f"[{self.username}] Registered with server.")
        # Start listener thread
        threading.Thread(target=self.listen, daemon=True).start()
        return True

    def listen(self):
        while True:
            msg = recv_json(self.sock)
            if msg is None:
                print("[INFO] Server disconnected.")
                break
            mtype = msg.get("type")
            if mtype == "DELIVER":
                sender = msg["from"]
                payload = msg["payload"]
                # First show ciphertext (as required)
                print(f"\n[INCOMING] From {sender} (ciphertext): {json.dumps(payload)}")
                # Log ciphertext to messages.json
                json_log_append(self.messages_file, {"direction":"in", "from": sender, "ciphertext": payload, "timestamp": time.time()})
                # Determine if this is a session key or a message
                if payload.get("payload_type") == "SESSION_KEY":
                    # decrypt RSA-encrypted session key
                    enc_key_b64 = payload["enc_session_key_b64"]
                    enc_key = base64.b64decode(enc_key_b64)
                    cipher_rsa = PKCS1_OAEP.new(self.privkey)
                    raw_key = cipher_rsa.decrypt(enc_key)
                    with self.lock:
                        self.session_keys[sender] = raw_key
                    print(f"[{self.username}] Decrypted session key from {sender}.")
                elif payload.get("payload_type") == "MSG":
                    # decrypt AES-GCM payload: we expect nonce_b64, ciphertext_b64, tag_b64
                    nonce = base64.b64decode(payload["nonce_b64"])
                    ct = base64.b64decode(payload["ciphertext_b64"])
                    tag = base64.b64decode(payload["tag_b64"])
                    with self.lock:
                        sk = self.session_keys.get(sender)
                    if not sk:
                        print(f"[{self.username}] No session key for {sender} — cannot decrypt.")
                        json_log_append(self.messages_file, {"direction":"in", "from": sender, "plaintext": None, "error": "no session key", "timestamp": time.time()})
                        continue
                    cipher = AES.new(sk, AES.MODE_GCM, nonce=nonce)
                    try:
                        plaintext = cipher.decrypt_and_verify(ct, tag).decode('utf-8')
                    except Exception as e:
                        plaintext = None
                        print("[DECRYPT ERROR]", e)
                    # Immediately after printing ciphertext, display decrypted plaintext (assignment requirement)
                    print(f"[DECRYPTED from {sender}]: {plaintext}")
                    json_log_append(self.messages_file, {"direction":"in", "from": sender, "ciphertext": payload, "plaintext": plaintext, "timestamp": time.time()})
                else:
                    print("[SERVER] unknown payload type")
            elif mtype == "PUBKEY":
                # received in response to a pubkey query
                print("[SERVER] PUBKEY reply received (not directly handled).")
            elif mtype == "ERROR":
                print("[SERVER ERROR]", msg.get("message"))
            elif mtype == "FORWARDED":
                # Acknowledgement after sending via server
                pass
            else:
                print("[SERVER] Unknown message type:", mtype)

    def query_pubkey(self, username):
        send_json(self.sock, {"type":"QUERY_PUBKEY", "username": username})
        # server responds asynchronously; easier to call a synchronous tiny socket for pubkey query
        # but to keep code simple: query and read immediate response (blocking)
        # Workaround: open a new short-lived socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))
        send_json(s, {"type":"QUERY_PUBKEY", "username": username})
        resp = recv_json(s)
        s.close()
        if resp and resp.get("type") == "PUBKEY":
            return resp["pubkey_pem"]
        return None

    def send_session_key(self, recipient):
        # retrieve recipient pubkey from server
        pub_pem = self.query_pubkey(recipient)
        if not pub_pem:
            print("Cannot find recipient pubkey.")
            return
        recipient_pub = RSA.import_key(pub_pem.encode('utf-8'))
        # generate AES session key (256 bit)
        session_key = get_random_bytes(32)
        # encrypt session key with recipient's RSA public key (OAEP)
        cipher_rsa = PKCS1_OAEP.new(recipient_pub)
        enc_key = cipher_rsa.encrypt(session_key)
        enc_key_b64 = base64.b64encode(enc_key).decode('utf-8')
        payload = {
            "payload_type": "SESSION_KEY",
            "enc_session_key_b64": enc_key_b64
        }
        send_json(self.sock, {"type":"FORWARD", "sender": self.username, "recipient": recipient, "payload": payload})
        # store session key locally (for ourselves) so we can send AES messages
        with self.lock:
            self.session_keys[recipient] = session_key
        # Also log that we sent session key (ciphertext only) to messages.json
        json_log_append(self.messages_file, {"direction":"out", "to": recipient, "ciphertext": payload, "timestamp": time.time()})
        print(f"[{self.username}] Session key generated and sent to {recipient} (encrypted with their RSA key).")

    def send_text_message(self, recipient, text):
        with self.lock:
            sk = self.session_keys.get(recipient)
        if not sk:
            print("No session key for recipient. Use 'sendkey <recipient>' first.")
            return
        # AES-GCM encrypt
        nonce = get_random_bytes(12)
        cipher = AES.new(sk, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
        payload = {
            "payload_type": "MSG",
            "nonce_b64": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext_b64": base64.b64encode(ct).decode('utf-8'),
            "tag_b64": base64.b64encode(tag).decode('utf-8'),
        }
        send_json(self.sock, {"type":"FORWARD", "sender": self.username, "recipient": recipient, "payload": payload})
        # Log both ciphertext and plaintext to messages.json (requirement: each client must maintain messages.json containing both encrypted and decrypted)
        json_log_append(self.messages_file, {"direction":"out", "to": recipient, "ciphertext": payload, "plaintext": text, "timestamp": time.time()})
        print(f"[{self.username}] Sent encrypted message to {recipient}.")

def print_help():
    print("Commands:")
    print("  sendkey <recipient>    -- generate AES session key and send it encrypted to recipient")
    print("  msg <recipient> <text> -- encrypt text with session key and send")
    print("  quit                   -- exit")

def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)
    username = sys.argv[1]
    client = Client(username)
    if not client.connect():
        return
    print_help()
    # interactive loop
    while True:
        try:
            cmd = input(f"[{username}]> ").strip()
        except EOFError:
            break
        if not cmd:
            continue
        parts = cmd.split(" ", 2)
        if parts[0] == "sendkey" and len(parts) >= 2:
            recipient = parts[1]
            client.send_session_key(recipient)
        elif parts[0] == "msg" and len(parts) >= 3:
            recipient = parts[1]
            text = parts[2]
            client.send_text_message(recipient, text)
        elif parts[0] == "quit":
            print("Exiting.")
            client.sock.close()
            break
        elif parts[0] == "help":
            print_help()
        else:
            print("Unknown command. Type 'help'.")

if __name__ == "__main__":
    main()
