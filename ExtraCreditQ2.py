import socket
import threading
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
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

        # Diffie-Hellman parameters (public base and prime)
        self.p = 23  # Example prime (should be much larger in production)
        self.g = 5   # Example base (should be a primitive root modulo p)

        # Generate private keys
        self.private_key = get_random_bytes(16)  # Secret key for Alice/Bob
        self.private_key_int = int.from_bytes(self.private_key, 'big')

        self.public_key = pow(self.g, self.private_key_int, self.p)  # Alice's/Bob's public key

        self.shared_secret = None
        self.socket = None
        self.connection = None

        self.setup_network()

    def generate_shared_secret(self, received_public_key):
        """Generate the shared secret using Diffie-Hellman"""
        # Compute the shared secret
        self.shared_secret = pow(received_public_key, self.private_key_int, self.p)
        self.display_message("System", f"Shared secret established: {self.shared_secret}")

        # Derive AES key from the shared secret
        self.current_key = SHA256.new(str(self.shared_secret).encode()).digest()

    def encrypt_message(self, plaintext):
        """Encrypt plaintext using AES in CBC mode"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.current_key, AES.MODE_CBC, iv)
        padded_msg = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_msg)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def decrypt_message(self, b64_ciphertext):
        """Decrypt ciphertext using AES in CBC mode"""
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
        """Send encrypted message over the network"""
        message = self.msg_entry.get()
        if not message or not self.connection:
            return

        try:
            # Encrypt and send the message
            ciphertext = self.encrypt_message(message)
            self.connection.sendall(ciphertext.encode('utf-8'))

            # Display message
            self.display_message("You (encrypted)", ciphertext)
            self.display_message("You", message)
            self.msg_entry.delete(0, tk.END)
        except Exception as e:
            self.display_message("System", f"Error sending message: {str(e)}")

    def receive_messages(self):
        """Listen for incoming messages"""
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

                # Display message
                self.display_message("Peer (encrypted)", ciphertext)
                self.display_message("Peer", plaintext)
            except Exception as e:
                self.display_message("System", f"Error receiving message: {str(e)}")
                break

    def setup_network(self):
        """Setup the network connection"""
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
        """Start listening for incoming connections"""
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
        """Accept incoming connection and perform key exchange"""
        self.connection, addr = self.socket.accept()
        self.display_message("System", f"Connected to {addr}")

        # Receive public key and generate shared secret
        public_key = int(self.connection.recv(4096).decode('utf-8'))
        self.generate_shared_secret(public_key)

        # Send own public key to peer
        self.connection.sendall(str(self.public_key).encode('utf-8'))

        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def connect_to_peer(self):
        """Connect to peer and perform key exchange"""
        host, port = self.peer_entry.get().split(":")
        port = int(port)

        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((host, port))
            self.display_message("System", f"Connected to {host}:{port}")

            # Send own public key
            self.connection.sendall(str(self.public_key).encode('utf-8'))

            # Receive peer's public key and generate shared secret
            peer_public_key = int(self.connection.recv(4096).decode('utf-8'))
            self.generate_shared_secret(peer_public_key)

            # Start receiving messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.net_window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")

    def display_message(self, sender, message):
        """Display message in the chat"""
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
