#!/usr/bin/env python3
import socket
import threading
import json
import base64

HOST = '127.0.0.1'
PORT = 9000

clients = {}      # username -> (conn, addr, pubkey_pem)
clients_lock = threading.Lock()

def recv_json(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if b"\n" in chunk:
            break
    try:
        text = data.decode('utf-8').strip()
        return json.loads(text)
    except Exception as e:
        print("Error decoding JSON:", e)
        return None

def send_json(conn, obj):
    raw = (json.dumps(obj) + "\n").encode('utf-8')
    conn.sendall(raw)

def handle_client(conn, addr):
    username = None
    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break
            mtype = msg.get("type")
            if mtype == "REGISTER":
                username = msg["username"]
                pubkey_pem = msg["pubkey_pem"]
                with clients_lock:
                    clients[username] = (conn, addr, pubkey_pem)
                print(f"[SERVER] Registered {username} from {addr}")
                send_json(conn, {"type":"REGISTERED", "ok":True})
            elif mtype == "FORWARD":
                # FORWARD contains: sender, recipient, payload (opaque dict)
                sender = msg["sender"]
                recipient = msg["recipient"]
                payload = msg["payload"]   # dict — server won't decrypt
                # Log the incoming encrypted payload at server console
                print(f"[SERVER] Incoming from {sender} -> {recipient} (encrypted): {json.dumps(payload)}")
                # Forward to recipient if connected
                with clients_lock:
                    target = clients.get(recipient)
                if target:
                    target_conn = target[0]
                    forward = {"type":"DELIVER", "from": sender, "payload": payload}
                    send_json(target_conn, forward)
                    send_json(conn, {"type":"FORWARDED", "ok":True})
                else:
                    send_json(conn, {"type":"ERROR", "message":"recipient not connected"})
            elif mtype == "QUERY_PUBKEY":
                # Respond with pubkey_pem of queried username if available
                q = msg["username"]
                with clients_lock:
                    got = clients.get(q)
                if got:
                    send_json(conn, {"type":"PUBKEY", "username": q, "pubkey_pem": got[2]})
                else:
                    send_json(conn, {"type":"ERROR", "message":"user not found"})
            else:
                send_json(conn, {"type":"ERROR", "message":"unknown message type"})
    except Exception as e:
        print("[SERVER] Exception:", e)
    finally:
        if username:
            with clients_lock:
                existing = clients.get(username)
                if existing and existing[0] == conn:
                    del clients[username]
            print(f"[SERVER] {username} disconnected")
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("[SERVER] Shutting down")
    finally:
        s.close()

if __name__ == "__main__":
    main()
