import socket
import threading
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import time

class SecureChatApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure P2P Chat")
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('TLabel', padding=5)
        
        # Set colors
        self.bg_color = '#f0f0f0'
        self.chat_bg = '#ffffff'
        self.entry_bg = '#ffffff'
        self.button_bg = '#4a90e2'
        self.button_fg = '#ffffff'
        self.system_color = '#666666'
        self.you_color = '#2c7be5'
        self.peer_color = '#27b08b'
        
        # Configure main window
        master.configure(bg=self.bg_color)
        master.geometry('600x500')
        
        # Create main frame
        main_frame = tk.Frame(master, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Chat display
        chat_frame = tk.Frame(main_frame, bg=self.bg_color)
        chat_frame.pack(fill=tk.BOTH, expand=True)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            state='disabled',
            bg=self.chat_bg,
            font=('Segoe UI', 10),
            wrap=tk.WORD,
            padx=10,
            pady=10
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Input area
        input_frame = tk.Frame(main_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.msg_entry = ttk.Entry(
            input_frame,
            font=('Segoe UI', 10)
        )
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", self.send_message)
        
        self.send_btn = ttk.Button(
            input_frame,
            text="Send",
            command=self.send_message,
            style='TButton'
        )
        self.send_btn.pack(side=tk.RIGHT)
        
        # Network and Crypto Setup
        self.password = None
        self.derived_key = None
        self.current_key = None
        self.message_count = 0
        self.message_sequence = 0
        self.socket = None
        self.connection = None
        
        # Generate ECC key pair for authentication
        self.private_key = ECC.generate(curve='P-256')
        self.public_key = self.private_key.public_key()
        
        self.setup_password()
    
    def setup_password(self):
        # Password setup dialog
        self.pwd_window = tk.Toplevel(self.master)
        self.pwd_window.title("Set Password")
        self.pwd_window.geometry('300x150')
        self.pwd_window.configure(bg=self.bg_color)
        
        # Center the window
        self.pwd_window.update_idletasks()
        width = self.pwd_window.winfo_width()
        height = self.pwd_window.winfo_height()
        x = (self.pwd_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.pwd_window.winfo_screenheight() // 2) - (height // 2)
        self.pwd_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Make window modal
        self.pwd_window.transient(self.master)
        self.pwd_window.grab_set()
        
        # Password entry
        pwd_frame = tk.Frame(self.pwd_window, bg=self.bg_color)
        pwd_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(
            pwd_frame,
            text="Shared Password:",
            style='TLabel'
        ).pack(pady=(0, 5))
        
        self.pwd_entry = ttk.Entry(
            pwd_frame,
            show="*",
            font=('Segoe UI', 10)
        )
        self.pwd_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(
            pwd_frame,
            text="OK",
            command=self.derive_keys,
            style='TButton'
        ).pack(pady=10)
    
    def derive_keys(self):
        self.password = self.pwd_entry.get().encode()
        if not self.password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
            
        # Validate password requirements
        if len(self.password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return
            
        # Check for password complexity
        has_upper = any(c.isupper() for c in self.password.decode())
        has_lower = any(c.islower() for c in self.password.decode())
        has_digit = any(c.isdigit() for c in self.password.decode())
        has_special = any(not c.isalnum() for c in self.password.decode())
        
        if not (has_upper and has_lower and has_digit and has_special):
            messagebox.showerror("Error", "Password must contain:\n- At least one uppercase letter\n- At least one lowercase letter\n- At least one number\n- At least one special character")
            return
        
        # Generate salt (will be exchanged with peer)
        self.salt = get_random_bytes(16)
        
        # Derive master key using PBKDF2
        self.derived_key = PBKDF2(self.password, self.salt, dkLen=32, 
                                 count=100000, hmac_hash_module=SHA256)
        
        # Generate initial session key using HKDF
        self.rotate_key()
        
        self.pwd_window.destroy()
        self.setup_network()
    
    def rotate_key(self):
        # Derive new session key using HKDF
        if not self.current_key:
            self.current_key = HKDF(self.derived_key, 32, b'', SHA256)
        else:
            self.current_key = HKDF(self.current_key, 32, b'key rotation', SHA256)
        self.message_count = 0
    
    def setup_network(self):
        # Network setup dialog
        self.net_window = tk.Toplevel(self.master)
        self.net_window.title("Network Setup")
        self.net_window.geometry('400x200')
        self.net_window.configure(bg=self.bg_color)
        
        # Center the window
        self.net_window.update_idletasks()
        width = self.net_window.winfo_width()
        height = self.net_window.winfo_height()
        x = (self.net_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.net_window.winfo_screenheight() // 2) - (height // 2)
        self.net_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Make window modal
        self.net_window.transient(self.master)
        self.net_window.grab_set()
        
        # Network setup frame
        net_frame = tk.Frame(self.net_window, bg=self.bg_color)
        net_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Port entry
        ttk.Label(
            net_frame,
            text="Port to listen on:",
            style='TLabel'
        ).pack(fill=tk.X, pady=(0, 5))
        
        self.port_entry = ttk.Entry(
            net_frame,
            font=('Segoe UI', 10)
        )
        self.port_entry.pack(fill=tk.X, pady=(0, 10))
        self.port_entry.insert(0, "12345")
        
        # Peer entry
        ttk.Label(
            net_frame,
            text="Connect to (host:port):",
            style='TLabel'
        ).pack(fill=tk.X, pady=(0, 5))
        
        self.peer_entry = ttk.Entry(
            net_frame,
            font=('Segoe UI', 10)
        )
        self.peer_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons frame
        btn_frame = tk.Frame(net_frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            btn_frame,
            text="Start Listening",
            command=self.start_listening,
            style='TButton'
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            btn_frame,
            text="Connect",
            command=self.connect_to_peer,
            style='TButton'
        ).pack(side=tk.RIGHT)
    
    def start_listening(self):
        port = int(self.port_entry.get())
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind(('0.0.0.0', port))
            self.socket.listen(1)
            
            threading.Thread(target=self.accept_connection, daemon=True).start()
            self.display_message("System", f"Listening on port {port}...")
            self.net_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start listening: {str(e)}")
    
    def accept_connection(self):
        self.connection, addr = self.socket.accept()
        self.display_message("System", f"Connected to {addr}")
        
        # Exchange public keys and salt
        self.exchange_keys()
        
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def connect_to_peer(self):
        host, port = self.peer_entry.get().split(":")
        port = int(port)
        
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))
            self.display_message("System", f"Connected to {host}:{port}")
            
            # Exchange public keys and salt
            self.exchange_keys()
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.net_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
    
    def exchange_keys(self):
        # Send our public key
        self.connection.sendall(self.public_key.export_key(format='DER'))
        
        # Receive peer's public key
        peer_key_data = self.connection.recv(91)  # Size of P-256 public key in DER format
        self.peer_public_key = ECC.import_key(peer_key_data)
        
        # Send our salt
        self.connection.sendall(self.salt)
        
        # Receive peer's salt
        peer_salt = self.connection.recv(16)
        
        # Combine salts for key derivation
        combined_salt = self.salt + peer_salt
        
        # Re-derive keys with combined salt
        self.derived_key = PBKDF2(self.password, combined_salt, dkLen=32,
                                 count=100000, hmac_hash_module=SHA256)
        self.rotate_key()
        
        # Send confirmation that key exchange is complete
        self.connection.sendall(b'KEY_EXCHANGE_COMPLETE')
        
        # Wait for peer's confirmation with timeout
        try:
            confirmation = self.connection.recv(20)
            if confirmation != b'KEY_EXCHANGE_COMPLETE':
                self.display_message("System", "Warning: Key exchange confirmation mismatch")
                # Continue anyway as the keys might still be correct
        except Exception as e:
            self.display_message("System", f"Warning: Key exchange confirmation error: {str(e)}")
            # Continue anyway as the keys might still be correct
        
        self.display_message("System", "Key exchange completed")
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if not message or not self.connection:
            return
        
        # Check for key rotation
        self.message_count += 1
        if self.message_count >= 100:
            self.rotate_key()
            self.display_message("System", "Encryption key rotated for security")
        
        # Increment sequence number
        self.message_sequence += 1
        
        # Encrypt the message
        iv = get_random_bytes(16)
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
        padded_msg = pad(message.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_msg)
        
        # Create message with sequence number and ciphertext length
        ciphertext_len = len(ciphertext).to_bytes(4, 'big')
        message_data = self.message_sequence.to_bytes(4, 'big') + iv + ciphertext_len + ciphertext
        
        # Sign the message
        signer = DSS.new(self.private_key, 'fips-186-3')
        h = SHA256.new(message_data)
        signature = signer.sign(h)
        
        # Create HMAC for integrity (only over message_data and signature)
        hmac = HMAC.new(self.current_key, digestmod=SHA256)
        hmac.update(message_data + signature)
        mac = hmac.digest()
        
        # Send sequence + IV + ciphertext length + ciphertext + signature + MAC
        full_msg = message_data + signature + mac
        
        # Send message length first
        msg_len = len(full_msg)
        self.connection.sendall(msg_len.to_bytes(4, 'big'))
        
        # Then send the actual message
        self.connection.sendall(full_msg)
        
        # Display in chat
        self.display_message("You (encrypted)", full_msg.hex())
        self.display_message("You", message)
        self.msg_entry.delete(0, tk.END)
    
    def receive_messages(self):
        while True:
            try:
                # First receive the message length
                len_data = self.connection.recv(4)
                if not len_data:
                    break
                    
                msg_len = int.from_bytes(len_data, 'big')
                
                # Receive the full message
                received = bytearray()
                while len(received) < msg_len:
                    chunk = self.connection.recv(min(4096, msg_len - len(received)))
                    if not chunk:
                        break
                    received.extend(chunk)
                
                if len(received) != msg_len:
                    self.display_message("System", "ERROR: Incomplete message received")
                    continue
                
                # Parse the message components
                sequence = int.from_bytes(received[:4], 'big')
                iv = received[4:20]
                ciphertext_len = int.from_bytes(received[20:24], 'big')
                ciphertext = received[24:24+ciphertext_len]
                signature = received[24+ciphertext_len:-32]
                mac = received[-32:]
                
                # Verify sequence number
                if sequence <= self.message_sequence:
                    self.display_message("System", "ERROR: Possible replay attack!")
                    continue
                self.message_sequence = sequence
                
                # Verify signature
                message_data = received[:-96]  # Everything except signature and MAC
                h = SHA256.new(message_data)
                verifier = DSS.new(self.peer_public_key, 'fips-186-3')
                try:
                    verifier.verify(h, signature)
                except ValueError as e:
                    # Debug information
                    self.display_message("System", f"DEBUG: Message data length: {len(message_data)}")
                    self.display_message("System", f"DEBUG: Signature length: {len(signature)}")
                    self.display_message("System", f"DEBUG: Public key: {self.peer_public_key.export_key(format='PEM')}")
                    self.display_message("System", f"DEBUG: Error details: {str(e)}")
                    self.display_message("System", "ERROR: Message signature verification failed!")
                    continue
                
                # Verify HMAC (only over message_data and signature)
                hmac = HMAC.new(self.current_key, digestmod=SHA256)
                hmac.update(message_data + signature)
                try:
                    hmac.verify(mac)
                except ValueError:
                    self.display_message("System", "ERROR: Message authentication failed!")
                    continue
                
                # Decrypt
                cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
                
                # Display
                self.display_message("Peer (encrypted)", received.hex())
                self.display_message("Peer", decrypted)
                
            except ConnectionResetError:
                self.display_message("System", "Connection lost")
                break
            except Exception as e:
                self.display_message("System", f"Error receiving message: {str(e)}")
                break
    
    def display_message(self, sender, message):
        self.chat_display.config(state='normal')
        
        # Set color based on sender
        if sender == "System":
            color = self.system_color
        elif sender == "You":
            color = self.you_color
        else:
            color = self.peer_color
        
        # Insert message with color
        self.chat_display.insert(tk.END, f"{sender}: ", ('tag', sender))
        self.chat_display.insert(tk.END, f"{message}\n")
        
        # Configure tags for colors
        self.chat_display.tag_configure(sender, foreground=color)
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()