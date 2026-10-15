import ggwave
import pyaudio
import socket
import threading
import time
import os
import secrets
import base64
import hashlib
import ipaddress
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# Cryptography primitives for ECDH and AES-128 (Fernet)
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# --- GLOBAL CONFIGURATION ---
PORT = 9999
DOWNLOAD_DIR = "./downloads"
HANDSHAKE_WINDOW_SEC = 30  # Time allowed for receivers to type the PIN
STREAM_TIMEOUT_SEC = 15.0  # Timeout for active file transfer chunks

os.makedirs(DOWNLOAD_DIR, exist_ok=True)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_unique_filepath(directory, filename):
    """Prevents silent file overwrites by appending (1), (2), etc. if the file exists."""
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base} ({counter}){ext}")
        counter += 1
    return candidate


class PeerNodeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SonicByte")
        self.root.geometry("500x420")
        self.root.configure(bg="white")

        self.my_ip = get_local_ip()
        self.is_listening = True
        self.app_running = True

        # Acoustic Spam Cooldown
        self.last_prompt_time = 0

        # --- GUI Elements (Black & White, Simple Font) ---
        self.font_standard = ("Arial", 10)
        self.font_bold = ("Arial", 10, "bold")

        self.ip_label = tk.Label(
            root, text=f"My Local IP: {self.my_ip}", bg="white", fg="black", font=self.font_bold
        )
        self.ip_label.pack(pady=10)

        self.display_pin_var = tk.StringVar(value="Status: Idle")
        self.pin_display = tk.Label(
            root, textvariable=self.display_pin_var, bg="white", fg="black", font=("Arial", 12, "bold")
        )
        self.pin_display.pack(pady=5)

        self.send_button = tk.Button(
            root, text="Select & Send File", command=self.trigger_send_thread,
            bg="black", fg="white", font=self.font_bold, width=20, height=2
        )
        self.send_button.pack(pady=10)

        self.log_area = tk.Text(
            root, height=12, width=60, bg="white", fg="black",
            font=self.font_standard, state=tk.DISABLED, relief=tk.SOLID, borderwidth=1
        )
        self.log_area.pack(pady=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.log_message("System Initialized...")
        self.log_message("Listening for incoming signals...")

        self.listener_thread = threading.Thread(target=self._acoustic_listener, daemon=True)
        self.listener_thread.start()

    def on_close(self):
        """Cleanly shuts down the application."""
        self.app_running = False
        self.is_listening = False
        self.root.destroy()

    # --- Thread-Safe UI Helpers ---
    def log_message(self, message):
        """Schedules a log update safely on the main Tkinter thread."""
        self.root.after(0, self._append_log, message)

    def _append_log(self, message):
        if not self.app_running:
            return
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    def set_status(self, text):
        """Thread-safe status label update."""
        self.root.after(0, self.display_pin_var.set, text)

    def set_send_button_state(self, state):
        """Thread-safe button state update."""
        self.root.after(0, lambda: self.send_button.config(state=state))

    # --- Helper Functions for Secure Comms ---
    @staticmethod
    def recv_exact(conn, num_bytes):
        """Reads an exact number of bytes or raises ConnectionError on unexpected EOF."""
        data = bytearray()
        while len(data) < num_bytes:
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                raise ConnectionError("Peer closed the connection unexpectedly.")
            data.extend(packet)
        return bytes(data)

    def send_enc_msg(self, conn, cipher, text):
        """Encrypts and sends a UTF-8 string safely."""
        enc = cipher.encrypt(text.encode('utf-8'))
        conn.sendall(len(enc).to_bytes(4, 'big') + enc)

    def recv_enc_msg(self, conn, cipher, max_len=4096):
        """Safely receives and decrypts a text message with strict length limits."""
        length_bytes = self.recv_exact(conn, 4)
        length = int.from_bytes(length_bytes, 'big')
        if length <= 0 or length > max_len:
            raise ValueError(f"Invalid message payload size: {length} bytes.")
        data = self.recv_exact(conn, length)
        return cipher.decrypt(data).decode('utf-8')

    def perform_ecdh_exchange(self, conn, pin, is_server=False):
        """
        Executes ECDH Key Exchange and binds the derived key to the 6-digit PIN via HKDF.
        Prevents passive sniffing and active PIN harvesting.
        """
        priv_key = ec.generate_private_key(ec.SECP256R1())
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if is_server:
            peer_len = int.from_bytes(self.recv_exact(conn, 4), 'big')
            if peer_len <= 0 or peer_len > 1024:
                raise ValueError("Invalid public key size.")
            peer_pub_bytes = self.recv_exact(conn, peer_len)
            conn.sendall(len(pub_bytes).to_bytes(4, 'big') + pub_bytes)
        else:
            conn.sendall(len(pub_bytes).to_bytes(4, 'big') + pub_bytes)
            peer_len = int.from_bytes(self.recv_exact(conn, 4), 'big')
            if peer_len <= 0 or peer_len > 1024:
                raise ValueError("Invalid public key size.")
            peer_pub_bytes = self.recv_exact(conn, peer_len)

        peer_pub_key = serialization.load_pem_public_key(peer_pub_bytes)
        shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)

        # Bind the derived AES key to the shared secret AND the human-entered PIN
        pin_salt = hashlib.sha256(pin.encode('utf-8')).digest()
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pin_salt,
            info=b'sonicbyte_ecdh_key_v2'
        ).derive(shared_secret)

        return Fernet(base64.urlsafe_b64encode(derived_key))

    # --- Acoustic Discovery ---
    def _acoustic_listener(self):
        p = pyaudio.PyAudio()
        instance = ggwave.init()
        stream = None

        try:
            stream = p.open(
                format=pyaudio.paFloat32, channels=1, rate=48000,
                input=True, frames_per_buffer=1024
            )
        except Exception as e:
            self.log_message(f"Microphone error: {e}")
            ggwave.free(instance)
            p.terminate()
            return

        try:
            while self.app_running:
                if not self.is_listening:
                    time.sleep(0.3)
                    continue

                try:
                    data = stream.read(1024, exception_on_overflow=False)
                    res = ggwave.decode(instance, data)

                    if res:
                        payload = res.decode('utf-8', errors='ignore').strip()
                        if payload.startswith("CONNECT:"):
                            parts = payload.split(":")
                            if len(parts) == 3:
                                sender_ip = parts[1]
                                timestamp = int(parts[2])

                                # Validate IP format
                                ipaddress.ip_address(sender_ip)

                                # Ignore our own acoustic reflection if any
                                if sender_ip == self.my_ip and not self.is_listening:
                                    continue

                                # Replay Attack Prevention (60s window)
                                if abs(int(time.time()) - timestamp) > 60:
                                    continue

                                # Rate Limiting (Anti-Spam)
                                if time.time() - self.last_prompt_time < 15:
                                    self.log_message("Rate limit active: Ignored audio spam.")
                                    continue

                                self.last_prompt_time = time.time()
                                self.is_listening = False
                                self.log_message(f"Secure signal from {sender_ip}. Awaiting PIN...")
                                self.root.after(0, self.prompt_for_pin, sender_ip)
                except Exception:
                    continue
        finally:
            if stream:
                stream.stop_stream()
                stream.close()
            ggwave.free(instance)
            p.terminate()

    def prompt_for_pin(self, sender_ip):
        pin = simpledialog.askstring(
            "Incoming Transfer",
            f"Enter the 6-digit Security PIN from {sender_ip}:",
            parent=self.root
        )
        if pin and len(pin.strip()) > 0:
            threading.Thread(
                target=self.download_file, args=(sender_ip, pin.strip()), daemon=True
            ).start()
        else:
            self.log_message(f"Transfer from {sender_ip} canceled.")
            self.is_listening = True

    def trigger_send_thread(self):
        file_path = filedialog.askopenfilename(title="Select a file to send")
        if file_path:
            confirm = messagebox.askyesno(
                "Confirm Transfer",
                f"Securely broadcast this file?\n\n{os.path.basename(file_path)}"
            )
            if confirm:
                threading.Thread(target=self.send_file, args=(file_path,), daemon=True).start()
            else:
                self.log_message("Transfer canceled.")

    # --- Sender Logic ---
    def send_file(self, target_file_path):
        self.is_listening = False
        self.set_send_button_state(tk.DISABLED)
        server = None
        connected_clients = []

        try:
            # 1. Calculate Pre-Flight Checksum
            self.log_message("Calculating file integrity...")
            sha256 = hashlib.sha256()
            with open(target_file_path, "rb") as f:
                while b := f.read(65536):
                    sha256.update(b)
            file_hash = sha256.hexdigest()

            current_pin = f"{secrets.randbelow(900000) + 100000}"
            self.set_status(f"TELL RECEIVER THIS PIN: {current_pin}")

            # 2. Open TCP Server BEFORE playing audio so fast peers never get "Connection Refused"
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.my_ip, PORT))
            server.listen(10)
            server.settimeout(0.5)

            # 3. Broadcast Audio Handshake
            payload = f"CONNECT:{self.my_ip}:{int(time.time())}"
            p = pyaudio.PyAudio()
            instance = ggwave.init()
            try:
                waveform = ggwave.encode(payload, protocolId=1, volume=100, instance=instance)
                self.log_message("Broadcasting secure audio handshake...")
                stream = p.open(format=pyaudio.paFloat32, channels=1, rate=48000, output=True)
                stream.write(waveform)
                stream.stop_stream()
                stream.close()
            finally:
                ggwave.free(instance)
                p.terminate()

            self.log_message(f"Waiting {HANDSHAKE_WINDOW_SEC}s for authorized peers to connect...")

            end_time = time.time() + HANDSHAKE_WINDOW_SEC
            while time.time() < end_time:
                try:
                    conn, addr = server.accept()
                    conn.settimeout(5.0)

                    try:
                        cipher = self.perform_ecdh_exchange(conn, current_pin, is_server=True)
                        # Verify peer derived the exact same PIN-bound key
                        auth_token = self.recv_enc_msg(conn, cipher)
                        if auth_token == "AUTH_VERIFY":
                            self.send_enc_msg(conn, cipher, "OK")
                            conn.settimeout(STREAM_TIMEOUT_SEC)
                            connected_clients.append((conn, cipher, addr[0]))
                            self.log_message(f"Peer {addr[0]} authenticated.")
                        else:
                            conn.close()
                    except (InvalidToken, ValueError, ConnectionError):
                        # InvalidToken triggers automatically when the peer enters the wrong PIN
                        try:
                            conn.close()
                        except Exception:
                            pass
                        self.log_message(f"Peer {addr[0]} denied (Wrong PIN or failed handshake).")

                except socket.timeout:
                    continue
                except Exception:
                    continue

            if not connected_clients:
                self.log_message("No peers joined. Transfer aborted.")
                return

            self.log_message(f"Gathering complete. Streaming to {len(connected_clients)} device(s)...")
            file_name = os.path.basename(target_file_path)

            # 4. Send Filename and Checksum Header to active clients
            active_clients = []
            for client_conn, cipher, ip in connected_clients:
                try:
                    self.send_enc_msg(client_conn, cipher, f"{file_name}|{file_hash}")
                    active_clients.append((client_conn, cipher, ip))
                except Exception as e:
                    self.log_message(f"Peer {ip} dropped during header: {e}")
                    client_conn.close()

            connected_clients = active_clients
            if not connected_clients:
                self.log_message("All peers disconnected before streaming.")
                return

            # 5. Stream File Chunks
            bytes_sent = 0
            with open(target_file_path, "rb") as f:
                while chunk := f.read(65536):
                    still_alive = []
                    for client_conn, cipher, ip in connected_clients:
                        try:
                            enc_chunk = cipher.encrypt(chunk)
                            client_conn.sendall(len(enc_chunk).to_bytes(4, 'big') + enc_chunk)
                            still_alive.append((client_conn, cipher, ip))
                        except Exception as e:
                            self.log_message(f"Peer {ip} disconnected mid-transfer: {e}")
                            try:
                                client_conn.close()
                            except Exception:
                                pass
                    connected_clients = still_alive
                    if not connected_clients:
                        raise ConnectionError("All receivers disconnected during transfer.")
                    bytes_sent += len(chunk)

            self.log_message(f"Encrypted broadcast complete! Sent {bytes_sent} bytes.")

        except Exception as e:
            self.log_message(f"Error during transfer: {e}")
        finally:
            for client_conn, _, _ in connected_clients:
                try:
                    client_conn.close()
                except Exception:
                    pass
            if server:
                try:
                    server.close()
                except Exception:
                    pass
            self.set_status("Status: Idle")
            self.set_send_button_state(tk.NORMAL)
            self.is_listening = True
            self.log_message("Returned to listening mode.")

    # --- Receiver Logic ---
    def download_file(self, sender_ip, entered_pin):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5.0)
        self.log_message(f"Connecting to {sender_ip}...")
        output_path = None
        transfer_complete = False

        try:
            client.connect((sender_ip, PORT))

            # 1. Negotiate PIN-bound ECDH and verify key
            cipher = self.perform_ecdh_exchange(client, entered_pin, is_server=False)
            self.send_enc_msg(client, cipher, "AUTH_VERIFY")

            response = self.recv_enc_msg(client, cipher)
            if response != "OK":
                self.log_message("Transfer denied: Incorrect PIN.")
                return

            # Sender waits up to HANDSHAKE_WINDOW_SEC for other peers before streaming
            client.settimeout(HANDSHAKE_WINDOW_SEC + 10.0)
            self.log_message("PIN accepted. Waiting for sender to start broadcast...")

            header_data = self.recv_enc_msg(client, cipher)
            # Use rsplit so filenames containing '|' don't break unpacking
            original_filename, expected_hash = header_data.rsplit('|', 1)

            # Switch to tighter timeout for active chunk streaming
            client.settimeout(STREAM_TIMEOUT_SEC)

            safe_filename = os.path.basename(original_filename.strip().replace("\\", "/"))
            if not safe_filename:
                safe_filename = "received_file"

            output_path = get_unique_filepath(DOWNLOAD_DIR, safe_filename)
            self.log_message(f"Receiving file: {os.path.basename(output_path)}")

            bytes_received = 0
            receiver_hash = hashlib.sha256()

            with open(output_path, "wb") as f:
                while True:
                    # Read 4-byte chunk length prefix (clean EOF returns b"")
                    chunk_len_bytes = bytearray()
                    while len(chunk_len_bytes) < 4:
                        packet = client.recv(4 - len(chunk_len_bytes))
                        if not packet:
                            break
                        chunk_len_bytes.extend(packet)

                    if not chunk_len_bytes:
                        break  # Clean end of stream
                    if len(chunk_len_bytes) < 4:
                        raise ConnectionError("Incomplete chunk header received.")

                    chunk_len = int.from_bytes(chunk_len_bytes, 'big')
                    if chunk_len <= 0 or chunk_len > 200000:
                        raise ValueError("Incoming encrypted chunk size out of bounds.")

                    enc_chunk = self.recv_exact(client, chunk_len)
                    dec_chunk = cipher.decrypt(enc_chunk)
                    f.write(dec_chunk)
                    receiver_hash.update(dec_chunk)
                    bytes_received += len(dec_chunk)

            # Final Integrity Check
            if receiver_hash.hexdigest() == expected_hash.strip():
                transfer_complete = True
                self.log_message(f"Saved to {output_path} ({bytes_received} bytes)")
                self.log_message("✅ Integrity Verified: File matches sender perfectly.")
            else:
                self.log_message("⚠️ WARNING: Checksum mismatch! Deleting corrupted file.")

        except InvalidToken:
            self.log_message("Transfer denied: Incorrect PIN or corrupted cipher stream.")
        except Exception as e:
            self.log_message(f"Transfer failed: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass
            # Clean up partial or corrupted file if transfer failed
            if output_path and not transfer_complete and os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            self.is_listening = True


if __name__ == "__main__":
    root = tk.Tk()
    app = PeerNodeGUI(root)
    root.mainloop()
