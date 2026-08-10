import ggwave
import pyaudio
import socket
import threading
import time
import os
import secrets
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# Cryptography primitives for ECDH and AES-128
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# --- GLOBAL CONFIGURATION ---
PORT = 9999
DOWNLOAD_DIR = "./downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class PeerNodeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SonicByte")
        self.root.geometry("500x420")
        self.root.configure(bg="white")
        
        self.my_ip = get_local_ip()
        self.is_listening = True
        
        # --- PATCH 2: Acoustic Spam Cooldown ---
        self.last_prompt_time = 0
        
        # --- GUI Elements (Black & White, Simple Font) ---
        self.font_standard = ("Arial", 10)
        self.font_bold = ("Arial", 10, "bold")

        self.ip_label = tk.Label(root, text=f"My Local IP: {self.my_ip}", bg="white", fg="black", font=self.font_bold)
        self.ip_label.pack(pady=10)
        
        self.display_pin_var = tk.StringVar(value="Status: Idle")
        self.pin_display = tk.Label(root, textvariable=self.display_pin_var, bg="white", fg="black", font=("Arial", 12, "bold"))
        self.pin_display.pack(pady=5)

        self.send_button = tk.Button(root, text="Select & Send File", command=self.trigger_send_thread, 
                                     bg="black", fg="white", font=self.font_bold, width=20, height=2)
        self.send_button.pack(pady=10)

        self.log_area = tk.Text(root, height=12, width=60, bg="white", fg="black", font=self.font_standard, state=tk.DISABLED, relief=tk.SOLID, borderwidth=1)
        self.log_area.pack(pady=10)

        self.log_message("System Initialized....")
        self.log_message("Listening for incoming signals...")
        
        self.listener_thread = threading.Thread(target=self._acoustic_listener, daemon=True)
        self.listener_thread.start()

    def log_message(self, message):
        """Safely updates the text log from any thread."""
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)
        self.root.update()

    # --- Helper Functions for Secure Comms ---
    def send_enc_msg(self, conn, cipher, text):
        """Encrypts and sends a text message safely."""
        enc = cipher.encrypt(text.encode('utf-8'))
        conn.sendall(len(enc).to_bytes(4, 'big'))
        conn.sendall(enc)

    def recv_enc_msg(self, conn, cipher):
        """Safely receives and decrypts a text message with strict length limits."""
        length_bytes = conn.recv(4)
        if not length_bytes: return None
        length = int.from_bytes(length_bytes, 'big')
        if length > 2048: raise ValueError("Message payload too large (Anti-DoS).")
        data = b""
        while len(data) < length:
            data += conn.recv(length - len(data))
        return cipher.decrypt(data).decode('utf-8')

    def perform_ecdh_exchange(self, conn, is_server=False):
        """Executes Elliptic-Curve Diffie-Hellman Key Exchange and returns Fernet cipher."""
        # 1. Generate local ECDH Keypair
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        if is_server:
            # Server receives first, then sends
            peer_len = int.from_bytes(conn.recv(4), 'big')
            if peer_len > 1024: raise ValueError("Invalid public key size.")
            peer_pub_bytes = b""
            while len(peer_pub_bytes) < peer_len:
                peer_pub_bytes += conn.recv(peer_len - len(peer_pub_bytes))
            
            conn.sendall(len(pub_bytes).to_bytes(4, 'big'))
            conn.sendall(pub_bytes)
        else:
            # Client sends first, then receives
            conn.sendall(len(pub_bytes).to_bytes(4, 'big'))
            conn.sendall(pub_bytes)
            
            peer_len = int.from_bytes(conn.recv(4), 'big')
            if peer_len > 1024: raise ValueError("Invalid public key size.")
            peer_pub_bytes = b""
            while len(peer_pub_bytes) < peer_len:
                peer_pub_bytes += conn.recv(peer_len - len(peer_pub_bytes))

        # 2. Derive Shared Secret and AES Key
        peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
        shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'sonicbyte_ecdh_key'
        ).derive(shared_secret)
        
        return Fernet(base64.urlsafe_b64encode(derived_key))

    def _acoustic_listener(self):
        p = pyaudio.PyAudio()
        instance = ggwave.init()
        stream = p.open(format=pyaudio.paFloat32, channels=1, rate=48000, input=True, frames_per_buffer=1024)
        
        while True:
            if not self.is_listening:
                time.sleep(0.5)
                continue

            try:
                data = stream.read(1024, exception_on_overflow=False)
                res = ggwave.decode(instance, data)
                
                if res:
                    payload = res.decode('utf-8')
                    if payload.startswith("CONNECT:"):
                        parts = payload.split(":")
                        if len(parts) == 3:
                            sender_ip = parts[1]
                            timestamp = int(parts[2])
                            
                            # Replay Attack Prevention
                            if abs(int(time.time()) - timestamp) > 60:
                                continue
                            
                            # --- PATCH 2: Rate Limiting (Anti-Spam) ---
                            if time.time() - self.last_prompt_time < 15:
                                self.log_message("Rate limit active: Ignored audio spam.")
                                continue
                                
                            self.last_prompt_time = time.time()
                            self.is_listening = False
                            self.log_message(f"Secure signal from {sender_ip}. Awaiting PIN...")
                            self.root.after(0, self.prompt_for_pin, sender_ip)
            except Exception:
                pass
                
    def prompt_for_pin(self, sender_ip):
        pin = simpledialog.askstring("Incoming Transfer", f"Enter the 6-digit Security PIN from {sender_ip}:", parent=self.root)
        if pin and len(pin.strip()) > 0:
            threading.Thread(target=self.download_file, args=(sender_ip, pin.strip()), daemon=True).start()
        else:
            self.log_message(f"Transfer from {sender_ip} canceled.")
            self.is_listening = True

    def trigger_send_thread(self):
        file_path = filedialog.askopenfilename(title="Select a file to send")
        if file_path:
            confirm = messagebox.askyesno("Confirm Transfer", f"Securely broadcast this file?\n\n{os.path.basename(file_path)}")
            if confirm:
                threading.Thread(target=self.send_file, args=(file_path,), daemon=True).start()
            else:
                self.log_message("Transfer canceled.")

    def send_file(self, target_file_path):
        self.is_listening = False
        self.send_button.config(state=tk.DISABLED)
        
        # --- PATCH 4: Calculate Pre-Flight Checksum ---
        self.log_message("Calculating file integrity...")
        sha256 = hashlib.sha256()
        with open(target_file_path, "rb") as f:
            while b := f.read(65536):
                sha256.update(b)
        file_hash = sha256.hexdigest()
        
        current_pin = str(secrets.randbelow(900000) + 100000)
# Use .after(0, ...) to force the main UI thread to update the text safely
        self.root.after(0, self.display_pin_var.set, f"TELL RECEIVER THIS PIN: {current_pin}")
        
        payload = f"CONNECT:{self.my_ip}:{int(time.time())}"
        
        p = pyaudio.PyAudio()
        instance = ggwave.init()
        waveform = ggwave.encode(payload, protocolId=1, volume=100, instance=instance)
        
        self.log_message("Broadcasting secure audio handshake...")
        stream = p.open(format=pyaudio.paFloat32, channels=1, rate=48000, output=True)
        stream.write(waveform)
        stream.stop_stream()
        stream.close()
        p.terminate()
        ggwave.free(instance)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server.bind((self.my_ip, PORT))
        
        server.listen(10)
        # --- PATCH 3: Aggressive Connection Timeout ---
        server.settimeout(0.5) 
        
        self.log_message("Waiting for authorized peers to connect...")
        
        connected_clients = []
        end_time = time.time() + 10
        
        try:
            while time.time() < end_time:
                try:
                    conn, addr = server.accept()
                    conn.settimeout(1.0) # Drop fast if peer stalls
                    
                    # --- PATCH 1: Authenticate via ECDH Tunnel ---
                    cipher = self.perform_ecdh_exchange(conn, is_server=True)
                    received_pin = self.recv_enc_msg(conn, cipher)
                        
                    if received_pin == current_pin:
                        self.send_enc_msg(conn, cipher, "OK")
                        conn.settimeout(None) 
                        connected_clients.append((conn, cipher))
                        self.log_message(f"Peer {addr[0]} authenticated.")
                    else:
                        self.send_enc_msg(conn, cipher, "DENIED")
                        conn.close()
                        self.log_message(f"Peer {addr[0]} denied (Wrong PIN).")
                        
                except socket.timeout:
                    continue
                except Exception:
                    continue
            
            if not connected_clients:
                self.log_message("No peers joined. Transfer aborted.")
                return

            self.log_message(f"Gathering complete. Streaming to {len(connected_clients)} devices...")
            
            file_name = os.path.basename(target_file_path)
            
            # Send Filename and Checksum
            for client_conn, cipher in connected_clients:
                try:
                    self.send_enc_msg(client_conn, cipher, f"{file_name}|{file_hash}")
                except Exception:
                    pass
            
            bytes_sent = 0
            with open(target_file_path, "rb") as f:
                while chunk := f.read(65536): 
                    for client_conn, cipher in connected_clients:
                        try:
                            enc_chunk = cipher.encrypt(chunk)
                            client_conn.sendall(len(enc_chunk).to_bytes(4, 'big'))
                            client_conn.sendall(enc_chunk)
                        except Exception:
                            pass 
                    bytes_sent += len(chunk)
                    
            self.log_message(f"Encrypted broadcast complete! Sent {bytes_sent} bytes.")
            
        except Exception as e:
            self.log_message(f"Error during transfer: {e}")
        finally:
            for client_conn, _ in connected_clients:
                client_conn.close()
            server.close()
            self.is_listening = True
            self.send_button.config(state=tk.NORMAL)
            self.display_pin_var.set("Status: Idle")
            self.log_message("Returned to listening mode.")

    def download_file(self, sender_ip, entered_pin):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0) # Network drop prevention
        self.log_message(f"Connecting to {sender_ip}...")
        
        try:
            client.connect((sender_ip, PORT))
            
            # --- PATCH 1: Negotiate ECDH and Send PIN securely ---
            cipher = self.perform_ecdh_exchange(client, is_server=False)
            self.send_enc_msg(client, cipher, entered_pin)
            
            response = self.recv_enc_msg(client, cipher)
            if response != "OK":
                self.log_message("Transfer denied: Incorrect PIN.")
                return
                
            client.settimeout(None) # Remove timeout for file data
            self.log_message("PIN accepted. Receiving data...")
            
            header_data = self.recv_enc_msg(client, cipher)
            original_filename, expected_hash = header_data.split('|')
            
            safe_filename = os.path.basename(original_filename.strip().replace("\\", "/"))
            output_path = os.path.join(DOWNLOAD_DIR, safe_filename)
            
            self.log_message(f"Receiving file: {safe_filename}")
            
            bytes_received = 0
            receiver_hash = hashlib.sha256()
            
            with open(output_path, "wb") as f:
                while True:
                    chunk_len_bytes = client.recv(4)
                    if not chunk_len_bytes:
                        break
                        
                    chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                    if chunk_len > 200000: 
                        raise ValueError("Incoming encrypted chunk too large.")
                    
                    enc_chunk = b""
                    while len(enc_chunk) < chunk_len:
                        enc_chunk += client.recv(chunk_len - len(enc_chunk))
                        
                    dec_chunk = cipher.decrypt(enc_chunk)
                    f.write(dec_chunk)
                    receiver_hash.update(dec_chunk) # Continuously verify integrity
                    bytes_received += len(dec_chunk)
            
            self.log_message(f"Decrypted & Saved to {DOWNLOAD_DIR} ({bytes_received} bytes)")
            
            # --- PATCH 4: Final Integrity Check ---
            if receiver_hash.hexdigest() == expected_hash.strip():
                self.log_message("✅ Integrity Verified: File matches sender perfectly.")
            else:
                self.log_message("⚠️ WARNING: Checksum mismatch! File is corrupted.")
                
        except Exception as e:
            self.log_message(f"Transfer failed: {e}")
        finally:
            client.close()
            self.is_listening = True 

if __name__ == "__main__":
    root = tk.Tk()
    app = PeerNodeGUI(root)
    root.mainloop()
