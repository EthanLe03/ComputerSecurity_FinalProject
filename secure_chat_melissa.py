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
import base64

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
        self.last_rotation = time.time()
        self.KEY_ROTATION_COUNT = 100  # Rotate after 100 messages
        self.KEY_ROTATION_TIME = 600   # Rotate every 10 minutes
        self.socket = None
        self.connection = None
        
        # Generate ECC key pair for authentication
        self.private_key = ECC.generate(curve='P-256')
        self.public_key = self.private_key.public_key()
        
        self.setup_password()
    
    def derive_key(self, password, nonce):
        """Derive a key using PBKDF2 with a fixed salt and nonce."""
        SALT = b'secure_salt'  # Fixed salt for PBKDF2
        key = PBKDF2(
            password,
            SALT + nonce.to_bytes(4, 'big'),
            dkLen=32,  # AES-256 key size
            count=100000,
            hmac_hash_module=SHA256
        )
        return key
    
    def rotate_key(self):
        """Rotate the encryption key based on message count or time."""
        current_time = time.time()
        
        # Check if we need to rotate based on message count or time
        if (self.message_count >= self.KEY_ROTATION_COUNT or 
            (current_time - self.last_rotation) >= self.KEY_ROTATION_TIME):
            
            # Use HKDF to derive new key
            self.current_key = HKDF(
                self.derived_key,
                32,  # AES-256 key size
                b'key rotation ' + str(self.message_count).encode(),
                SHA256
            )
            
            # Reset counters
            self.message_count = 0
            self.last_rotation = current_time
            
            # Notify user
            self.display_message("System", "Encryption key rotated for security")
            self.display_message("System", f"Next rotation in {self.KEY_ROTATION_COUNT} messages or {self.KEY_ROTATION_TIME//60} minutes")
    
    def encrypt_message(self, plaintext):
        """Encrypt plaintext using AES in CBC mode."""
        iv = get_random_bytes(16)
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
        padded_msg = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_msg)
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt_message(self, b64_ciphertext):
        """Decrypt ciphertext using AES in CBC mode."""
        try:
            data = base64.b64decode(b64_ciphertext)
            iv = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            self.display_message("System", f"Decryption failed: {str(e)}")
            return "[Decryption Failed]"
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if not message or not self.connection:
            return
        
        try:
            # Check for key rotation
            self.rotate_key()
            
            # Encrypt and send the message
            ciphertext = self.encrypt_message(message)
            self.connection.sendall(ciphertext.encode('utf-8'))
            
            # Increment message count after successful send
            self.message_count += 1
            
            # Display in chat
            self.display_message("You (encrypted)", ciphertext)
            self.display_message("You", message)
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            self.display_message("System", f"Error sending message: {str(e)}")
    
    def receive_messages(self):
        while True:
            try:
                # Receive data
                data = self.connection.recv(4096)
                if not data:
                    self.display_message("System", "Connection closed by peer")
                    break
                
                # Decrypt and display the message
                ciphertext = data.decode('utf-8')
                plaintext = self.decrypt_message(ciphertext)
                
                # Increment message count after successful receive
                self.message_count += 1
                
                # Check for key rotation
                self.rotate_key()
                
                # Display message
                self.display_message("Peer (encrypted)", ciphertext)
                self.display_message("Peer", plaintext)
                
            except ConnectionResetError:
                self.display_message("System", "Connection lost")
                break
            except Exception as e:
                self.display_message("System", f"Error receiving message: {str(e)}")
                break
    
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
        
        # Derive initial key
        self.derived_key = self.derive_key(self.password, 0)
        self.current_key = self.derived_key
        
        self.pwd_window.destroy()
        self.setup_network()
    
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
        
        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def connect_to_peer(self):
        host, port = self.peer_entry.get().split(":")
        port = int(port)
        
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))
            self.display_message("System", f"Connected to {host}:{port}")
            
            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.net_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
    
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
