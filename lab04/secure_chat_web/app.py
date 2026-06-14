from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import socket
import threading
import struct
import json
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import dh

# Import our crypto helpers
from crypto_helper import (
    encrypt_aes, decrypt_aes,
    generate_rsa_keypair, encrypt_rsa, decrypt_rsa,
    generate_dh_parameters, serialize_dh_parameters, deserialize_dh_parameters,
    generate_dh_keypair, serialize_dh_public_key, deserialize_dh_public_key,
    derive_shared_secret, derive_aes_key
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'instagram_secure_chat_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active sessions: sid -> session details
# session details: { 'socket': sock, 'aes_key': key, 'username': name, 'protocol': proto, 'thread': t }
sessions = {}
sessions_lock = threading.Lock()

# ----------------- TCP Helper Functions -----------------

def send_msg(sock, data):
    """Send length-prefixed bytes data over TCP socket."""
    msg = struct.pack('>I', len(data)) + data
    sock.sendall(msg)

def recvall(sock, n):
    """Receive exactly n bytes or return None."""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def recv_msg(sock):
    """Receive a length-prefixed message from TCP socket."""
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

# ----------------- AES-RSA TCP Server -----------------

def aes_rsa_server_loop():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(10)
    print("[SERVER] AES-RSA TCP Server listening on 127.0.0.1:12345")
    
    # Generate server RSA keypair
    _, server_pub_pem = generate_rsa_keypair()
    
    clients = {}  # sock -> {'aes_key': aes_key, 'username': username}
    clients_lock = threading.Lock()
    
    def handle_client(sock, addr):
        username = None
        aes_key = None
        try:
            # 1. Send server's RSA public key
            send_msg(sock, server_pub_pem)
            
            # 2. Receive client's RSA public key
            client_pub_pem = recv_msg(sock)
            if not client_pub_pem:
                return
            
            # 3. Generate AES session key
            aes_key = get_random_bytes(16)
            
            # 4. Encrypt AES key using client's public key
            encrypted_aes_key = encrypt_rsa(client_pub_pem, aes_key)
            send_msg(sock, encrypted_aes_key)
            
            # Store client details
            with clients_lock:
                clients[sock] = {'aes_key': aes_key, 'username': None}
                
            # 5. Receive username (first encrypted message)
            init_msg_ciphertext = recv_msg(sock)
            if not init_msg_ciphertext:
                return
            init_msg = decrypt_aes(aes_key, init_msg_ciphertext)
            if init_msg.startswith("SYSTEM_USER:"):
                username = init_msg.split(":", 1)[1]
                with clients_lock:
                    clients[sock]['username'] = username
                print(f"[AES-RSA SERVER] User '{username}' connected from {addr}.")
                
                # Broadcast join notification
                with clients_lock:
                    for other_sock, info in clients.items():
                        if other_sock != sock and info['username'] is not None:
                            join_msg = f"SYSTEM_NOTIFICATION:{username} has joined the chat"
                            relayed_ciphertext = encrypt_aes(info['aes_key'], join_msg)
                            try:
                                send_msg(other_sock, relayed_ciphertext)
                            except Exception as e:
                                print(f"[AES-RSA SERVER] Broadcast join error: {e}")
            else:
                return
                
            # Receive loop
            while True:
                ciphertext = recv_msg(sock)
                if not ciphertext:
                    break
                
                # Decrypt message
                plaintext = decrypt_aes(aes_key, ciphertext)
                print(f"[AES-RSA SERVER] Recv from {username}: {plaintext}")
                
                # Broadcast message to all other clients
                with clients_lock:
                    for other_sock, info in clients.items():
                        if other_sock != sock and info['username'] is not None:
                            # Re-encrypt with recipient's AES key
                            relayed_ciphertext = encrypt_aes(info['aes_key'], plaintext)
                            try:
                                send_msg(other_sock, relayed_ciphertext)
                            except Exception as e:
                                print(f"[AES-RSA SERVER] Broadcast message error: {e}")
                            
        except Exception as e:
            print(f"[AES-RSA SERVER] Error handling client {addr}: {e}")
        finally:
            with clients_lock:
                if sock in clients:
                    username = clients[sock]['username']
                    del clients[sock]
                    
                    # Broadcast leave notification
                    if username:
                        for other_sock, info in clients.items():
                            if info['username'] is not None:
                                leave_msg = f"SYSTEM_NOTIFICATION:{username} has left the chat"
                                relayed_ciphertext = encrypt_aes(info['aes_key'], leave_msg)
                                try:
                                    send_msg(other_sock, relayed_ciphertext)
                                except Exception as e:
                                    print(f"[AES-RSA SERVER] Broadcast leave error: {e}")
            sock.close()
            if username:
                print(f"[AES-RSA SERVER] User '{username}' disconnected.")

    while True:
        try:
            sock, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except Exception as e:
            print(f"[AES-RSA SERVER] Accept error: {e}")
            break

# ----------------- DH-AES TCP Server -----------------

def dh_aes_server_loop():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 12346))
    server_socket.listen(10)
    print("[SERVER] DH-AES TCP Server listening on 127.0.0.1:12346")
    
    # Generate DH Parameters once at startup
    print("[SERVER] Generating Diffie-Hellman parameters (generator=2, key_size=1024)...")
    dh_parameters = generate_dh_parameters()
    dh_params_pem = serialize_dh_parameters(dh_parameters)
    
    # Generate Server DH keypair
    server_priv_key, server_pub_key = generate_dh_keypair(dh_parameters)
    server_pub_pem = serialize_dh_public_key(server_pub_key)
    
    clients = {}  # sock -> {'aes_key': aes_key, 'username': username}
    clients_lock = threading.Lock()
    
    def handle_client(sock, addr):
        username = None
        aes_key = None
        try:
            # 1. Send DH parameters
            send_msg(sock, dh_params_pem)
            
            # 2. Send Server DH Public Key
            send_msg(sock, server_pub_pem)
            
            # 3. Receive Client DH Public Key
            client_pub_pem = recv_msg(sock)
            if not client_pub_pem:
                return
            client_pub_key = deserialize_dh_public_key(client_pub_pem)
            
            # 4. Derive Shared Secret and AES session key
            shared_secret = derive_shared_secret(server_priv_key, client_pub_key)
            aes_key = derive_aes_key(shared_secret)
            
            # Store client details
            with clients_lock:
                clients[sock] = {'aes_key': aes_key, 'username': None}
                
            # 5. Receive username (first encrypted message)
            init_msg_ciphertext = recv_msg(sock)
            if not init_msg_ciphertext:
                return
            init_msg = decrypt_aes(aes_key, init_msg_ciphertext)
            if init_msg.startswith("SYSTEM_USER:"):
                username = init_msg.split(":", 1)[1]
                with clients_lock:
                    clients[sock]['username'] = username
                print(f"[DH-AES SERVER] User '{username}' connected from {addr}.")
                
                # Broadcast join notification
                with clients_lock:
                    for other_sock, info in clients.items():
                        if other_sock != sock and info['username'] is not None:
                            join_msg = f"SYSTEM_NOTIFICATION:{username} has joined the chat"
                            relayed_ciphertext = encrypt_aes(info['aes_key'], join_msg)
                            try:
                                send_msg(other_sock, relayed_ciphertext)
                            except Exception as e:
                                print(f"[DH-AES SERVER] Broadcast join error: {e}")
            else:
                return
                
            # Receive loop
            while True:
                ciphertext = recv_msg(sock)
                if not ciphertext:
                    break
                
                # Decrypt message
                plaintext = decrypt_aes(aes_key, ciphertext)
                print(f"[DH-AES SERVER] Recv from {username}: {plaintext}")
                
                # Broadcast message to all other clients
                with clients_lock:
                    for other_sock, info in clients.items():
                        if other_sock != sock and info['username'] is not None:
                            # Re-encrypt with recipient's AES key
                            relayed_ciphertext = encrypt_aes(info['aes_key'], plaintext)
                            try:
                                send_msg(other_sock, relayed_ciphertext)
                            except Exception as e:
                                print(f"[DH-AES SERVER] Broadcast message error: {e}")
                            
        except Exception as e:
            print(f"[DH-AES SERVER] Error handling client {addr}: {e}")
        finally:
            with clients_lock:
                if sock in clients:
                    username = clients[sock]['username']
                    del clients[sock]
                    
                    # Broadcast leave notification
                    if username:
                        for other_sock, info in clients.items():
                            if info['username'] is not None:
                                leave_msg = f"SYSTEM_NOTIFICATION:{username} has left the chat"
                                relayed_ciphertext = encrypt_aes(info['aes_key'], leave_msg)
                                try:
                                    send_msg(other_sock, relayed_ciphertext)
                                except Exception as e:
                                    print(f"[DH-AES SERVER] Broadcast leave error: {e}")
            sock.close()
            if username:
                print(f"[DH-AES SERVER] User '{username}' disconnected.")

    while True:
        try:
            sock, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except Exception as e:
            print(f"[DH-AES SERVER] Accept error: {e}")
            break

# ----------------- Web UI Client Receiver Loop -----------------

def client_recv_thread(sid, sock, aes_key):
    """Listens on the client TCP socket and forwards decrypted messages to the browser."""
    try:
        while True:
            ciphertext = recv_msg(sock)
            if not ciphertext:
                break
            
            # Decrypt the received ciphertext
            plaintext = decrypt_aes(aes_key, ciphertext)
            
            # Check for SYSTEM_NOTIFICATION
            if plaintext.startswith("SYSTEM_NOTIFICATION:"):
                sys_text = plaintext.split(":", 1)[1]
                socketio.emit('status_message', {
                    'text': sys_text,
                    'raw_hex': ciphertext.hex()
                }, room=sid)
            else:
                # Format: "sender:message"
                if ":" in plaintext:
                    sender, msg_text = plaintext.split(":", 1)
                else:
                    sender, msg_text = "System", plaintext
                    
                # Forward plaintext and raw encrypted hex to the browser
                socketio.emit('message_received', {
                    'sender': sender,
                    'text': msg_text,
                    'raw_hex': ciphertext.hex()
                }, room=sid)
    except Exception as e:
        print(f"[CLIENT LOOP] Error for session {sid}: {e}")
    finally:
        with sessions_lock:
            if sid in sessions:
                sock.close()
                del sessions[sid]
        socketio.emit('connection_lost', {}, room=sid)

# ----------------- Flask SocketIO Endpoints -----------------

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('join_chat')
def on_join_chat(data):
    username = data.get('username')
    protocol = data.get('protocol') # 'aes_rsa' or 'dh_aes'
    sid = request.sid
    
    if not username or not protocol:
        emit('handshake_error', {'message': 'Missing username or protocol.'})
        return

    def run_client_handshake():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == 'aes_rsa':
                socketio.emit('handshake_step', {'step': 'connect', 'text': 'Connecting to AES-RSA Server on port 12345...'}, room=sid)
                sock.connect(('127.0.0.1', 12345))
                
                # 1. Receive server RSA public key
                socketio.emit('handshake_step', {'step': 'recv_key', 'text': 'Received server public RSA key.'}, room=sid)
                server_pub_pem = recv_msg(sock)
                
                # 2. Generate client RSA keypair
                socketio.emit('handshake_step', {'step': 'gen_keys', 'text': 'Generating client 2048-bit RSA key pair...'}, room=sid)
                client_priv_pem, client_pub_pem = generate_rsa_keypair()
                
                # 3. Send client RSA public key to server
                socketio.emit('handshake_step', {'step': 'send_key', 'text': 'Sent client public RSA key to server.'}, room=sid)
                send_msg(sock, client_pub_pem)
                
                # 4. Receive encrypted AES session key
                socketio.emit('handshake_step', {'step': 'recv_aes', 'text': 'Received encrypted AES session key.'}, room=sid)
                encrypted_aes_key = recv_msg(sock)
                
                # 5. Decrypt AES key
                socketio.emit('handshake_step', {'step': 'decrypt_aes', 'text': 'Decrypting AES session key with client private RSA key...'}, room=sid)
                aes_key = decrypt_rsa(client_priv_pem, encrypted_aes_key)
                
                # 6. Send username encrypted with AES
                socketio.emit('handshake_step', {'step': 'send_username', 'text': f"Sending encrypted username '{username}' to establish session..."}, room=sid)
                init_msg = f"SYSTEM_USER:{username}"
                send_msg(sock, encrypt_aes(aes_key, init_msg))
                
                # Handshake complete
                socketio.emit('handshake_complete', {
                    'protocol_name': 'AES-256-RSA-OAEP',
                    'client_pub': client_pub_pem.decode('utf-8'),
                    'client_priv': client_priv_pem.decode('utf-8'),
                    'server_pub': server_pub_pem.decode('utf-8'),
                    'aes_key': aes_key.hex(),
                    'shared_secret': None
                }, room=sid)
                
            elif protocol == 'dh_aes':
                socketio.emit('handshake_step', {'step': 'connect', 'text': 'Connecting to Diffie-Hellman TCP Server on port 12346...'}, room=sid)
                sock.connect(('127.0.0.1', 12346))
                
                # 1. Receive DH parameters
                socketio.emit('handshake_step', {'step': 'recv_params', 'text': 'Received DH parameters from server.'}, room=sid)
                dh_params_pem = recv_msg(sock)
                dh_parameters = deserialize_dh_parameters(dh_params_pem)
                
                # 2. Receive Server DH public key
                socketio.emit('handshake_step', {'step': 'recv_key', 'text': "Received server public DH key."}, room=sid)
                server_pub_pem = recv_msg(sock)
                server_pub_key = deserialize_dh_public_key(server_pub_pem)
                
                # 3. Generate Client DH keypair
                socketio.emit('handshake_step', {'step': 'gen_keys', 'text': 'Generating client DH private & public keys...'}, room=sid)
                client_priv_key, client_pub_key = generate_dh_keypair(dh_parameters)
                client_pub_pem = serialize_dh_public_key(client_pub_key)
                
                # 4. Send Client DH public key
                socketio.emit('handshake_step', {'step': 'send_key', 'text': 'Sent client public DH key to server.'}, room=sid)
                send_msg(sock, client_pub_pem)
                
                # 5. Derive Shared Secret and AES session key
                socketio.emit('handshake_step', {'step': 'derive_secret', 'text': 'Exchanging keys and deriving Diffie-Hellman shared secret...'}, room=sid)
                shared_secret = derive_shared_secret(client_priv_key, server_pub_key)
                aes_key = derive_aes_key(shared_secret)
                
                # 6. Send username encrypted with AES
                socketio.emit('handshake_step', {'step': 'send_username', 'text': f"Sending encrypted username '{username}' to establish session..."}, room=sid)
                init_msg = f"SYSTEM_USER:{username}"
                send_msg(sock, encrypt_aes(aes_key, init_msg))
                
                # Handshake complete
                # Representing DH details
                socketio.emit('handshake_complete', {
                    'protocol_name': 'Diffie-Hellman + AES-CBC',
                    'client_pub': client_pub_pem.decode('utf-8'),
                    'client_priv': 'Generated DH Private Key (strictly local)',
                    'server_pub': server_pub_pem.decode('utf-8'),
                    'aes_key': aes_key.hex(),
                    'shared_secret': shared_secret.hex()
                }, room=sid)
                
            else:
                raise ValueError("Invalid protocol.")
                
            # Store session details
            t = threading.Thread(target=client_recv_thread, args=(sid, sock, aes_key), daemon=True)
            with sessions_lock:
                sessions[sid] = {
                    'socket': sock,
                    'aes_key': aes_key,
                    'username': username,
                    'protocol': protocol,
                    'thread': t
                }
            t.start()
            
        except Exception as e:
            print(f"[CLIENT HANDSHAKE ERROR] {e}")
            socketio.emit('handshake_error', {'message': f"Failed to connect or perform handshake: {str(e)}"}, room=sid)
            
    threading.Thread(target=run_client_handshake, daemon=True).start()

@socketio.on('send_chat_message')
def on_send_chat_message(data):
    sid = request.sid
    text = data.get('text')
    
    with sessions_lock:
        session = sessions.get(sid)
        
    if session and text:
        try:
            # Format: "sender_username:message_text"
            plaintext = f"{session['username']}:{text}"
            ciphertext = encrypt_aes(session['aes_key'], plaintext)
            
            # Send via TCP Socket
            send_msg(session['socket'], ciphertext)
            
            # Echo back to the sender's UI
            emit('message_sent', {
                'text': text,
                'raw_hex': ciphertext.hex()
            })
        except Exception as e:
            print(f"[SEND ERROR] Failed to send message for {sid}: {e}")
            emit('connection_lost', {})

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    with sessions_lock:
        session = sessions.get(sid)
        if session:
            try:
                session['socket'].close()
            except:
                pass
            del sessions[sid]
            print(f"[SESSION DISCONNECTED] Closed socket client for session {sid}.")

# ----------------- Main Entrypoint -----------------

if __name__ == '__main__':
    # Start AES-RSA TCP Socket Server in background
    threading.Thread(target=aes_rsa_server_loop, daemon=True).start()
    
    # Start DH-AES TCP Socket Server in background
    threading.Thread(target=dh_aes_server_loop, daemon=True).start()
    
    # Start Flask-SocketIO Web Server
    socketio.run(app, host='127.0.0.1', port=5000, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)
