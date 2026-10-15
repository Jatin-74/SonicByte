**SonicByte** is a zero-configuration, peer-to-peer local file transfer application that uses **data-over-sound (`ggwave`)** for device discovery and **PIN-bound Elliptic-Curve Diffie-Hellman (ECDH)** for encrypted TCP streaming.

No manual IP typing, no cloud intermediaries, and no external servers required—just play an audio chirp to pair devices in the same room and stream files directly over your local network.

---

## ✨ Key Features

* **Acoustic Discovery:** Broadcasts connection metadata (`IP + Timestamp`) over audible/near-ultrasonic sound waves using `ggwave`.
* **End-to-End Encryption:** Negotiates an ephemeral **SECP256R1 ECDH** key exchange for every transfer, deriving a session key via **HKDF-SHA256** bound to a 6-digit human-verified PIN and encrypting chunks with **Fernet (AES-128-CBC + HMAC-SHA256)**.
* **One-to-Many Broadcast:** A single acoustic chirp allows up to 10 nearby peers to authenticate and download the file simultaneously.
* **Built-In Hardening:**
  * **Replay Protection:** Rejects captured audio handshakes older than 60 seconds.
  * **Acoustic Rate-Limiting:** 15-second cooldown prevents audio-spam DoS popups.
  * **End-to-End Integrity:** Pre-flight and post-transfer **SHA-256** checksum verification automatically deletes corrupted or incomplete files.
  * **Path Traversal & Overwrite Protection:** Sanitizes incoming filenames and automatically renames duplicates (`file (1).ext`).

  ## 🔐 How the Protocol Works

1. **Pre-Flight Hashing:** When the sender selects a file, SonicByte calculates its **SHA-256** digest and generates a cryptographically random 6-digit PIN (`secrets`).
2. **Acoustic Bootstrap:** The sender opens a local TCP listener on port `9999` and emits an audio waveform encoding `CONNECT:<SENDER_IP>:<UNIX_TIMESTAMP>`.
3. **Timestamp & Cooldown Validation:** Receivers listening via microphone decode the audio, verify that the timestamp is within a 60-second window, and prompt the user for the 6-digit PIN.
4. **PIN-Bound ECDH Handshake:**
   * Sender and Receiver exchange ephemeral `SECP256R1` public keys over TCP.
   * Both sides compute the shared ECDH secret and pass it through **HKDF-SHA256**, using the SHA-256 hash of the 6-digit PIN as the cryptographic salt.
   * The receiver proves possession of the correct PIN by encrypting an `AUTH_VERIFY` token. If the PIN was entered incorrectly, decryption fails immediately (`InvalidToken`) and the connection is dropped.
5. **Encrypted Chunk Streaming:** The file is read in `64 KB` chunks, encrypted via **Fernet**, and streamed to all authenticated peers.
6. **Integrity Verification:** As chunks arrive, the receiver decrypts them to `./downloads/` while computing a running SHA-256 hash. If the final digest does not match the sender's pre-flight hash, the file is discarded.


## ⚠️ Troubleshooting

* **Receiver isn't picking up the audio signal:**
  Turn up the speaker volume on the sender device to 70–100%, minimize background noise, and make sure the OS microphone permissions are granted to your terminal or Python IDE.
* **Connection timed out after entering PIN:**
  Ensure both devices are on the same subnet (not isolated by Guest Wi-Fi client isolation) and that your OS firewall allows incoming TCP connections on port `9999`.
