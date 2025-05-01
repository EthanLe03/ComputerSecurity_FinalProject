import socket
import threading
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time

class SecureChatApp:
    def __init__(self, master):
        self.master = master
        master.title("Secure P2P Chat")
        
        # UI Elements
        self.chat_display = scrolledtext.ScrolledText(master, state='disabled')
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.msg_entry = tk.Entry(master)
        self.msg_entry.pack(padx=10, pady=5, fill=tk.X)
        self.msg_entry.bind("<Return>", self.send_message)
        
        self.send_btn = tk.Button(master, text="Send", command=self.send_message)
        self.send_btn.pack(padx=10, pady=5)
        
        # Network and Crypto Setup
        self.password = None
        self.derived_key = None
        self.current_key = None
        self.message_count = 0
        self.socket = None
        self.connection = None
        
        self.setup_password()
    
    def setup_password(self):
        # Password setup dialog
        self.pwd_window = tk.Toplevel(self.master)
        self.pwd_window.title("Set Password")
        
        tk.Label(self.pwd_window, text="Shared Password:").pack(padx=10, pady=5)
        self.pwd_entry = tk.Entry(self.pwd_window, show="*")
        self.pwd_entry.pack(padx=10, pady=5)
        
        tk.Button(self.pwd_window, text="OK", command=self.derive_keys).pack(padx=10, pady=10)
    
    def derive_keys(self):
        self.password = self.pwd_entry.get().encode()
        if not self.password:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        # Generate salt (would be shared between Alice and Bob in real setup)
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
        # Simple network setup dialog
        self.net_window = tk.Toplevel(self.master)
        self.net_window.title("Network Setup")
        
        tk.Label(self.net_window, text="Port to listen on:").pack(padx=10, pady=5)
        self.port_entry = tk.Entry(self.net_window)
        self.port_entry.pack(padx=10, pady=5)
        self.port_entry.insert(0, "12345")
        
        tk.Label(self.net_window, text="Connect to (host:port):").pack(padx=10, pady=5)
        self.peer_entry = tk.Entry(self.net_window)
        self.peer_entry.pack(padx=10, pady=5)
        
        tk.Button(self.net_window, text="Start Listening", 
                 command=self.start_listening).pack(side=tk.LEFT, padx=10, pady=10)
        tk.Button(self.net_window, text="Connect", 
                 command=self.connect_to_peer).pack(side=tk.RIGHT, padx=10, pady=10)
    
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
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def connect_to_peer(self):
        host, port = self.peer_entry.get().split(":")
        port = int(port)
        
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))
            self.display_message("System", f"Connected to {host}:{port}")
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.net_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if not message or not self.connection:
            return
        
        # Check for key rotation
        self.message_count += 1
        if self.message_count >= 100:
            self.rotate_key()
            self.display_message("System", "Encryption key rotated for security")
        
        # Encrypt the message
        iv = get_random_bytes(16)
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
        padded_msg = pad(message.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_msg)
        
        # Create HMAC for integrity
        hmac = HMAC.new(self.current_key, digestmod=SHA256)
        hmac.update(iv + ciphertext)
        mac = hmac.digest()
        
        # Send IV + ciphertext + MAC
        full_msg = iv + ciphertext + mac
        self.connection.sendall(full_msg)
        
        # Display in chat
        self.display_message("You (encrypted)", full_msg.hex())
        self.display_message("You", message)
        self.msg_entry.delete(0, tk.END)
    
    def receive_messages(self):
        while True:
            try:
                # Receive IV (16) + ciphertext + MAC (32)
                header = self.connection.recv(16)
                if not header:
                    break
                
                iv = header
                ciphertext_len = int.from_bytes(self.connection.recv(4), 'big')
                ciphertext = self.connection.recv(ciphertext_len)
                mac = self.connection.recv(32)
                
                # Verify HMAC
                hmac = HMAC.new(self.current_key, digestmod=SHA256)
                hmac.update(iv + ciphertext)
                try:
                    hmac.verify(mac)
                except ValueError:
                    self.display_message("System", "ERROR: Message authentication failed!")
                    continue
                
                # Decrypt
                cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
                
                # Display
                self.display_message("Peer (encrypted)", (iv + ciphertext + mac).hex())
                self.display_message("Peer", decrypted)
                
            except ConnectionResetError:
                self.display_message("System", "Connection lost")
                break
            except Exception as e:
                self.display_message("System", f"Error receiving message: {str(e)}")
                break
    
    def display_message(self, sender, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()