import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from PIL import Image, ImageTk  # Requires Pillow library
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64
import time
from datetime import datetime
from tkhtmlview import HTMLLabel  # Requires tkhtmlview library

# Constants
DEFAULT_PORT = 65432        # Default server port
DEFAULT_HOST = 'localhost'  # Default server host

# Utility Functions
def derive_key(passphrase, nonce):
    """Derive a 56-bit DES key using PBKDF2 with a fixed salt and nonce."""
    SALT = b'secure_salt'  # Fixed salt for PBKDF2
    # DES key is 8 bytes (64 bits), but only 56 bits are used
    key = PBKDF2(
        passphrase,
        SALT + nonce.to_bytes(4, 'big'),
        dkLen=8,
        count=1000,
        hmac_hash_module=SHA256  # Use PyCryptodome's SHA256
    )
    return key

def pad_pkcs5(text):
    """Apply PKCS#5 padding."""
    pad_len = 8 - (len(text) % 8)
    return text + bytes([pad_len] * pad_len)

def unpad_pkcs5(text):
    """Remove PKCS#5 padding."""
    pad_len = text[-1]
    return text[:-pad_len]

def get_current_timestamp():
    """Return current timestamp as a string."""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Cryptographic Functions
def encrypt_message(key, plaintext):
    """Encrypt plaintext using DES in CBC mode with PKCS#5 padding."""
    iv = get_random_bytes(8)  # DES block size is 8 bytes
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_text = pad_pkcs5(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded_text)
    # Encode IV + ciphertext for transmission
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_message(key, b64_ciphertext):
    """Decrypt ciphertext using DES in CBC mode with PKCS#5 padding."""
    try:
        data = base64.b64decode(b64_ciphertext)
        iv = data[:8]
        ciphertext = data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad_pkcs5(padded_plaintext)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError, UnicodeDecodeError):
        return "[Decryption Failed]"

# Networking Classes
class SecureChatBase:
    def __init__(self, gui, passphrase):
        self.gui = gui
        self.passphrase = passphrase
        self.nonce = 0
        self.key = derive_key(self.passphrase, self.nonce)
        self.message_count = 0
        self.last_rotation = time.time()
        self.lock = threading.Lock()

    def rotate_key(self):
        with self.lock:
            self.nonce += 1
            self.key = derive_key(self.passphrase, self.nonce)
            self.message_count = 0
            self.last_rotation = time.time()
            self.gui.display_system_message("Encryption key rotated.")

    def check_key_rotation(self):
        current_time = time.time()
        if self.message_count >= self.gui.KEY_ROTATION_COUNT or (current_time - self.last_rotation) >= self.gui.KEY_ROTATION_TIME:
            self.rotate_key()

    def send_encrypted(self, plaintext):
        ciphertext = encrypt_message(self.key, plaintext)
        self.send(ciphertext)
        self.message_count += 1
        self.check_key_rotation()
        return ciphertext

    def receive_decrypted(self, b64_ciphertext):
        plaintext = decrypt_message(self.key, b64_ciphertext)
        self.message_count += 1
        self.check_key_rotation()
        return plaintext

    def send(self, data):
        raise NotImplementedError

    def receive(self):
        raise NotImplementedError

class SecureChatServer(SecureChatBase):
    def __init__(self, gui, passphrase, host, port):
        super().__init__(gui, passphrase)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket = None
        self.connected = False
        try:
            self.server_socket.bind((host, port))
            self.server_socket.listen(1)
            self.gui.display_system_message(f"Server started on {host}:{port}. Waiting for connections...")
            # Start a separate thread to accept connections
            accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
            accept_thread.start()
        except Exception as e:
            self.gui.display_system_message(f"Server error: {e}")

    def accept_connections(self):
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.connected = True
            self.gui.display_system_message(f"Connected by {addr}")
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.gui.display_system_message(f"Error accepting connections: {e}")

    def send(self, data):
        if self.connected and self.client_socket:
            try:
                self.client_socket.sendall(data.encode('utf-8'))
                if self.gui.ciphertext_window:
                    self.gui.ciphertext_window.display_ciphertext("Sent", data)
            except Exception as e:
                self.gui.display_system_message(f"Failed to send message: {e}")

    def receive_loop(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.gui.display_system_message("Connection closed by the client.")
                    self.connected = False
                    break
                b64_ciphertext = data.decode('utf-8')
                plaintext = self.receive_decrypted(b64_ciphertext)
                self.gui.display_message("Alice", b64_ciphertext, plaintext)
                if self.gui.ciphertext_window:
                    self.gui.ciphertext_window.display_ciphertext("Received", b64_ciphertext)
            except Exception as e:
                self.gui.display_system_message(f"Error receiving data: {e}")
                self.connected = False
                break

class SecureChatClient(SecureChatBase):
    def __init__(self, gui, passphrase, host, port):
        super().__init__(gui, passphrase)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.connected = False
        self.connect_thread = threading.Thread(target=self.connect_to_server, daemon=True)
        self.connect_thread.start()

    def connect_to_server(self):
        try:
            self.client_socket.connect((self.host, self.port))
            self.connected = True
            self.gui.display_system_message(f"Connected to the server at {self.host}:{self.port}.")
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            self.gui.display_system_message(f"Connection error: {e}")

    def send(self, data):
        if self.connected and self.client_socket:
            try:
                self.client_socket.sendall(data.encode('utf-8'))
                if self.gui.ciphertext_window:
                    self.gui.ciphertext_window.display_ciphertext("Sent", data)
            except Exception as e:
                self.gui.display_system_message(f"Failed to send message: {e}")

    def receive_loop(self):
        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    self.gui.display_system_message("Connection closed by the server.")
                    self.connected = False
                    break
                b64_ciphertext = data.decode('utf-8')
                plaintext = self.receive_decrypted(b64_ciphertext)
                self.gui.display_message("Bob", b64_ciphertext, plaintext)
                if self.gui.ciphertext_window:
                    self.gui.ciphertext_window.display_ciphertext("Received", b64_ciphertext)
            except Exception as e:
                self.gui.display_system_message(f"Error receiving data: {e}")
                self.connected = False
                break

# Ciphertext Viewer Class (Third Window)
class CiphertextWindow:
    def __init__(self, master):
        self.master = master
        self.top = tk.Toplevel(master)
        self.top.title("Ciphertext Viewer")
        self.top.resizable(True, True)  # Allow resizing
        self.top.protocol("WM_DELETE_WINDOW", self.on_close)  # Handle window close

        # Add a gray border frame for debugging
        self.ciphertext_display_frame = tk.Frame(self.top, relief="solid")
        self.ciphertext_display_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Title Label inside the bordered frame
        title_label = tk.Label(self.ciphertext_display_frame, text="Ciphertext Traffic", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Messages Display using ScrolledText inside the bordered frame
        self.cipher_display = scrolledtext.ScrolledText(
            self.ciphertext_display_frame,
            wrap=tk.WORD,
            state='disabled',
            width=60,
            height=20,
            font=("Courier", 10)
        )
        self.cipher_display.pack(padx=10, pady=10, fill='both', expand=True)

    def on_close(self):
        # Allow the window to be closed
        self.top.destroy()

    def display_ciphertext(self, direction, ciphertext):
        self.cipher_display.config(state='normal')
        timestamp = get_current_timestamp()
        if direction == "Sent":
            prefix = "Sent"
            fg_color = "blue"
        else:
            prefix = "Received"
            fg_color = "red"
        self.cipher_display.insert(tk.END, f"{prefix} [{timestamp}]: {ciphertext}\n", direction)
        self.cipher_display.tag_config(direction, foreground=fg_color)
        self.cipher_display.see(tk.END)
        self.cipher_display.config(state='disabled')

    def position_window(self):
        """Position the Info window relative to the main chat window."""
        self.top.update_idletasks()
        main_x = self.master.winfo_x()
        main_y = self.master.winfo_y()
        main_width = self.master.winfo_width()
        main_height = self.master.winfo_height()

        info_width = 480
        info_height = 200

        # Position Info window centered relative to main window
        x = main_x + (main_width // 2) - (info_width // 2)
        y = main_y + main_height + 40

        self.top.geometry(f"{info_width}x{info_height}+{x}+{y}")

# Info Window using HTML
class InfoWindow:
    def __init__(self, master):
        self.master = master
        self.top = tk.Toplevel(master)
        self.top.title("Encryption & Decryption Info")
        self.top.geometry("800x600")  # Increased width
        self.top.resizable(True, True)  # Allow resizing

        # Add a light green border frame for debugging
        self.info_content_frame = tk.Frame(self.top, relief="solid")
        self.info_content_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Position the Info window relative to the main chat window
        self.position_window()

        # Make sure the info window is above the main window
        self.top.transient(master)
        self.top.grab_set()

        # Title Label inside the bordered frame
        title_label = tk.Label(self.info_content_frame, text="Encryption & Decryption Methods", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        # HTML Content
        html_content = """
        <h2>Encryption Process:</h2>
        <ol>
            <li><strong>Key Derivation:</strong>
                <ul>
                    <li>A DES key is derived from a passphrase using PBKDF2 with a fixed salt and a nonce.</li>
                    <li><code>Key = PBKDF2(passphrase, SALT + nonce, dkLen=8, count=1000, hmac=SHA256)</code></li>
                </ul>
            </li>
            <li><strong>Padding:</strong>
                <ul>
                    <li>The plaintext message is padded using PKCS#5 to ensure it fits the DES block size.</li>
                    <li><code>padded_text = plaintext + (8 - len(plaintext) % 8) * chr(8 - len(plaintext) % 8)</code></li>
                </ul>
            </li>
            <li><strong>Encryption:</strong>
                <ul>
                    <li>DES encryption is performed in CBC mode using the derived key and a randomly generated IV.</li>
                    <li><code>ciphertext = DES.new(key, DES.MODE_CBC, iv).encrypt(padded_text)</code></li>
                </ul>
            </li>
            <li><strong>Encoding:</strong>
                <ul>
                    <li>The IV and ciphertext are concatenated and encoded using Base64 for transmission.</li>
                    <li><code>b64_ciphertext = Base64Encode(iv + ciphertext)</code></li>
                </ul>
            </li>
        </ol>

        <h2>Decryption Process:</h2>
        <ol>
            <li><strong>Decoding:</strong>
                <ul>
                    <li>The received Base64-encoded ciphertext is decoded to retrieve the IV and ciphertext.</li>
                    <li><code>data = Base64Decode(b64_ciphertext)</code></li>
                </ul>
            </li>
            <li><strong>Decryption:</strong>
                <ul>
                    <li>DES decryption is performed in CBC mode using the derived key and the extracted IV.</li>
                    <li><code>padded_plaintext = DES.new(key, DES.MODE_CBC, iv).decrypt(ciphertext)</code></li>
                </ul>
            </li>
            <li><strong>Unpadding:</strong>
                <ul>
                    <li>The padding is removed to retrieve the original plaintext message.</li>
                    <li><code>plaintext = padded_plaintext[:-padded_plaintext[-1]]</code></li>
                </ul>
            </li>
        </ol>

        <h2>Key Rotation:</h2>
        <ul>
            <li>The encryption key is rotated after a specified number of messages or after a certain time interval to enhance security.</li>
            <li><code>if message_count >= KEY_ROTATION_COUNT or current_time - last_rotation >= KEY_ROTATION_TIME:</code></li>
            <li><code>&nbsp;&nbsp;&nbsp;&nbsp;rotate_key()</code></li>
        </ul>

        <h2>Security Features:</h2>
        <ul>
            <li><strong>CBC Mode:</strong> Ensures that identical plaintext blocks yield different ciphertexts by chaining encryption with previous blocks.</li>
            <li><strong>Unique IVs:</strong> A new Initialization Vector (IV) is generated for each message to prevent replay attacks and ensure ciphertext uniqueness.</li>
            <li><strong>Key Rotation:</strong> Regularly updating the encryption key minimizes the risk of key compromise.</li>
        </ul>
        """

        # HTML Label inside the bordered frame
        html_label = HTMLLabel(self.info_content_frame, html=html_content)
        html_label.pack(fill="both", expand=True, padx=10, pady=10)

    def position_window(self):
        """Position the Info window relative to the main chat window."""
        self.top.update_idletasks()
        main_x = self.master.winfo_x()
        main_y = self.master.winfo_y()
        main_width = self.master.winfo_width()
        main_height = self.master.winfo_height()

        info_width = 800
        info_height = 600

        # Position Info window centered relative to main window
        x = main_x + (main_width // 2) - (info_width // 2)
        y = main_y + (main_height // 2) - (info_height // 2)

        self.top.geometry(f"{info_width}x{info_height}+{x}+{y}")

# Startup UI Class (Redefined to eliminate duplicates)
class StartupUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure P2P Messaging Tool - Startup")
        self.master.geometry("600x500")  # Increased height for better layout
        self.master.resizable(False, False)

        # Center the startup window
        self.center_window()

        # Title Label
        title_label = tk.Label(master, text="Secure P2P Messaging Tool", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        # Role Selection Frame
        role_frame = tk.LabelFrame(master, text="Select Role", font=("Arial", 14), padx=20, pady=20)
        role_frame.pack(pady=10, padx=20, fill='x')

        self.role_var = tk.StringVar(value="server")

        server_radio = tk.Radiobutton(role_frame, text="Server (Bob)", variable=self.role_var, value="server", font=("Arial", 12))
        server_radio.pack(side='left', padx=20)

        client_radio = tk.Radiobutton(role_frame, text="Client (Alice)", variable=self.role_var, value="client", font=("Arial", 12))
        client_radio.pack(side='left', padx=20)

        # Connection Details Frame
        conn_frame = tk.LabelFrame(master, text="Connection Details", font=("Arial", 14), padx=20, pady=20)
        conn_frame.pack(pady=10, padx=20, fill='both', expand=True)

        # Host IP
        host_label = tk.Label(conn_frame, text="Host IP:", font=("Arial", 12), anchor='w')
        host_label.grid(row=0, column=0, sticky='w', pady=5)

        self.host_entry = tk.Entry(conn_frame, font=("Arial", 12))
        self.host_entry.grid(row=0, column=1, pady=5, sticky='ew')
        self.host_entry.insert(0, DEFAULT_HOST)

        # Port
        port_label = tk.Label(conn_frame, text="Port:", font=("Arial", 12), anchor='w')
        port_label.grid(row=1, column=0, sticky='w', pady=5)

        self.port_entry = tk.Entry(conn_frame, font=("Arial", 12))
        self.port_entry.grid(row=1, column=1, pady=5, sticky='ew')
        self.port_entry.insert(0, str(DEFAULT_PORT))

        # Passphrase
        passphrase_label = tk.Label(conn_frame, text="Passphrase:", font=("Arial", 12), anchor='w')
        passphrase_label.grid(row=2, column=0, sticky='w', pady=5)

        self.passphrase_entry = tk.Entry(conn_frame, font=("Arial", 12), show='*')
        self.passphrase_entry.grid(row=2, column=1, pady=5, sticky='ew')

        # Configure grid weights for responsiveness
        conn_frame.columnconfigure(1, weight=1)

        # Connect Button
        connect_button = tk.Button(master, text="Connect", font=("Arial", 14, "bold"), command=self.connect, width=20, bg="#4CAF50", fg="white")
        connect_button.pack(pady=30)

        # Bind Enter key to connect
        self.master.bind('<Return>', self.connect)

    def center_window(self):
        self.master.update_idletasks()
        width = self.master.winfo_width()
        height = self.master.winfo_height()
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        self.master.geometry(f"+{x}+{y}")

    def connect(self, event=None):
        role = self.role_var.get()
        is_server = True if role == "server" else False

        host = self.host_entry.get().strip()
        port_str = self.port_entry.get().strip()
        passphrase = self.passphrase_entry.get().strip()

        if not host:
            messagebox.showerror("Input Error", "Host IP is required.")
            return

        if not port_str.isdigit():
            messagebox.showerror("Input Error", "Port must be a number.")
            return

        port = int(port_str)

        if not passphrase:
            messagebox.showerror("Input Error", "Passphrase is required.")
            return

        # Proceed to open the main chat window
        self.master.destroy()
        root = tk.Tk()
        gui = ChatGUI(root, is_server, passphrase, host, port)
        root.mainloop()

# GUI Class
class ChatGUI:
    KEY_ROTATION_COUNT = 5       # Rotate key after every 5 messages
    KEY_ROTATION_TIME = 600      # Rotate key every 10 minutes (600 seconds)

    def __init__(self, root, is_server, passphrase, host, port):
        self.root = root
        self.root.title("Secure P2P Messaging Tool")
        self.root.geometry("475x600")
        self.root.resizable(False, False)
        self.is_server = is_server
        self.passphrase = passphrase
        self.host = host
        self.port = port
        self.user_role = "Bob" if self.is_server else "Alice"  # User's own role
        self.setup_ui()
        if self.is_server:
            self.chat = SecureChatServer(self, self.passphrase, self.host, self.port)
        else:
            self.chat = SecureChatClient(self, self.passphrase, self.host, self.port)

    def setup_ui(self):
        # Add a purple border frame for debugging
        self.header_frame = tk.Frame(self.root, relief="solid")
        self.header_frame.pack(padx=10, pady=5, fill='x')

        # Inner frame for header content
        header_inner_frame = tk.Frame(self.header_frame, bg="white")
        header_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Load Images Silently
        try:
            self.user_image = Image.open("user.png")
            self.user_image = self.user_image.resize((40, 40), Image.ANTIALIAS)
            self.user_photo = ImageTk.PhotoImage(self.user_image)
        except Exception:
            self.user_photo = None

        try:
            self.recipient_image = Image.open("recipient.png")
            self.recipient_image = self.recipient_image.resize((40, 40), Image.ANTIALIAS)
            self.recipient_photo = ImageTk.PhotoImage(self.recipient_image)
        except Exception:
            self.recipient_photo = None

        # User Info Frame with cyan border
        self.user_info_frame = tk.Frame(header_inner_frame, relief="solid")
        self.user_info_frame.pack(side='left', padx=(0, 10))

        user_inner_frame = tk.Frame(self.user_info_frame, bg="white")
        user_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        if self.user_photo:
            user_pic_label = tk.Label(user_inner_frame, image=self.user_photo, bg="white")
            user_pic_label.pack(side='left')
        else:
            user_pic_label = tk.Label(user_inner_frame, text=self.user_role[0], bg="#a2d5f2", fg='white',
                                      font=("Arial", 14, "bold"), width=2, height=1)
            user_pic_label.pack(side='left')

        user_name_label = tk.Label(user_inner_frame, text=self.user_role, bg="white", font=("Arial", 12, "bold"))
        user_name_label.pack(side='left', padx=5)

        # Arrow Label
        arrow_label = tk.Label(header_inner_frame, text="→", bg="white", font=("Arial", 16))
        arrow_label.pack(side='left')

        # Recipient Info Frame with magenta border
        self.recipient_info_frame = tk.Frame(header_inner_frame, relief="solid")
        self.recipient_info_frame.pack(side='left', padx=(10, 0))

        recipient_inner_frame = tk.Frame(self.recipient_info_frame, bg="white")
        recipient_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        recipient_name = "Alice" if self.is_server else "Bob"

        if self.recipient_photo:
            recipient_pic_label = tk.Label(recipient_inner_frame, image=self.recipient_photo, bg="white")
            recipient_pic_label.pack(side='left')
        else:
            recipient_pic_label = tk.Label(recipient_inner_frame, text=recipient_name[0], bg="#f2a2a2", fg='white',
                                          font=("Arial", 14, "bold"), width=2, height=1)
            recipient_pic_label.pack(side='left')

        recipient_name_label = tk.Label(recipient_inner_frame, text=recipient_name, bg="white", font=("Arial", 12, "bold"))
        recipient_name_label.pack(side='left', padx=5)

        # Buttons Frame with yellow border
        self.buttons_frame = tk.Frame(header_inner_frame, relief="solid")
        self.buttons_frame.pack(side='right', padx=(0, 10))

        buttons_inner_frame = tk.Frame(self.buttons_frame, bg="white")
        buttons_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Info Button
        info_button = tk.Button(buttons_inner_frame, text="ℹ️", command=self.show_info, font=("Arial", 12),
                                width=3, bg="white", relief="flat")
        info_button.pack(side='left', padx=(0, 5))

        # Ciphertext Viewer Button
        ciphertext_button = tk.Button(buttons_inner_frame, text="🔍", command=self.toggle_ciphertext_viewer, font=("Arial", 12),
                                      width=3, bg="white", relief="flat")
        ciphertext_button.pack(side='left')

        # Add a brown border frame for the canvas
        self.canvas_frame = tk.Frame(self.root, relief="solid")
        self.canvas_frame.pack(padx=10, pady=5, fill='both', expand=True)

        # Inner frame for canvas
        canvas_inner_frame = tk.Frame(self.canvas_frame, bg="white")
        canvas_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        # Messages Display using Canvas and Frames for better alignment
        self.canvas = tk.Canvas(canvas_inner_frame, bg="white", width=390)
        self.canvas.pack(padx=10, pady=5, fill='both', expand=True)

        self.messages_frame = tk.Frame(self.canvas, bg="white")
        self.canvas.create_window((0, 0), window=self.messages_frame, anchor='nw')

        self.messages_frame.bind("<Configure>", self.on_frame_configure)

        # Bind mouse wheel to scroll
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Add a pink border frame for the entry section
        self.entry_frame = tk.Frame(self.root, relief="solid")
        self.entry_frame.pack(padx=10, pady=5, fill='x')

        entry_inner_frame = tk.Frame(self.entry_frame, bg="white")
        entry_inner_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.message_var = tk.StringVar()
        self.message_entry = tk.Entry(
            entry_inner_frame,
            textvariable=self.message_var,
            font=("Arial", 12)
        )
        self.message_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            entry_inner_frame,
            text="Send",
            command=self.send_message,
            width=10,
            bg="#4CAF50",
            fg="white"
        )
        self.send_button.pack(side='left')

        # Initialize Ciphertext Viewer as None
        self.ciphertext_window = None

        # Bind the configure event to adjust wrap lengths on window resize (optional)
        self.root.bind("<Configure>", self.on_window_resize)

    def toggle_ciphertext_viewer(self):
        """Toggle the Ciphertext Viewer window."""
        if self.ciphertext_window and tk.Toplevel.winfo_exists(self.ciphertext_window.top):
            # If already open, focus it
            self.ciphertext_window.top.focus_force()
        else:
            # Open a new Ciphertext Viewer window
            self.ciphertext_window = CiphertextWindow(self.root)
            # Position the Ciphertext Viewer below the main chat window
            self.position_ciphertext_window()

    def position_ciphertext_window(self):
        """Position the Ciphertext Viewer below the main chat window."""
        if self.ciphertext_window:
            self.ciphertext_window.position_window()

    def generate_color(self, initials):
        """Generate a consistent color based on initials."""
        return "#%06x" % (hash(initials) % 0xFFFFFF)

    def on_frame_configure(self, event):
        """Reset the scroll region to encompass the inner frame"""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_mousewheel(self, event):
        """Scroll the canvas with mouse wheel"""
        # For Windows and MacOS
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        # For Linux, you might need to bind <Button-4> and <Button-5> instead

    def on_window_resize(self, event):
        """Handle window resize to adjust existing messages' wraplength."""
        for child in self.messages_frame.winfo_children():
            for widget in child.winfo_children():
                if isinstance(widget, tk.Label) and "Ciphertext:" not in widget.cget("text") and "System" not in widget.cget("text"):
                    # This is a plaintext label
                    new_wrap = max(int(self.root.winfo_width() * 0.8), 200)  # 80% of window width, with a min of 200px
                    widget.config(wraplength=new_wrap)

    def display_message(self, sender, ciphertext, plaintext):
        timestamp = get_current_timestamp()
        if sender == self.user_role:
            prefix = "You"
            alignment = 'e'  # East (Right)
            bg_color = "#a2d5f2"  # Light blue
            fg_color = "black"
        else:
            prefix = sender
            alignment = 'w'  # West (Left)
            bg_color = "#f2a2a2"  # Light red
            fg_color = "black"

        # Calculate wraplength: 80% of window width with a minimum of 200px
        wrap_length = 300

        # Create a frame for the message
        message_frame = tk.Frame(self.messages_frame, bg="white")

        # Make the message_frame fill the width
        message_frame.pack(fill='x', pady=2)

        # Create the message bubble
        bubble = tk.Frame(message_frame, bg=bg_color, padx=10, pady=5, bd=1, relief='solid')

        # Align the bubble to left or right
        if alignment == 'e':
            bubble.pack(anchor='e', padx=10, pady=2)
        else:
            bubble.pack(anchor='w', padx=10, pady=2)

        # Ciphertext label
        ciphertext_label = tk.Label(
            bubble,
            text=f"Ciphertext: {ciphertext}",
            font=("Arial", 8),
            fg='gray',
            bg=bg_color,
            wraplength=wrap_length,
            justify='left'
        )
        ciphertext_label.pack(anchor='w')

        # Plaintext label with alignment
        plaintext_label = tk.Label(
            bubble,
            text=plaintext,
            font=("Arial", 12),
            fg=fg_color,
            bg=bg_color,
            wraplength=wrap_length,
            justify='right' if alignment == 'e' else 'left',
            anchor='e' if alignment == 'e' else 'w'
        )
        plaintext_label.pack(anchor='e' if alignment == 'e' else 'w')

        # Timestamp label
        timestamp_label = tk.Label(
            bubble,
            text=timestamp,
            font=("Arial", 8, "italic"),
            fg='blue',
            bg=bg_color,
            anchor='e'
        )
        timestamp_label.pack(anchor='e')

        # Auto-scroll to the bottom
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def display_system_message(self, message):
        timestamp = get_current_timestamp()

        # Calculate wraplength: full width minus padding
        wrap_length = 400

        # Create a frame for the system message
        system_frame = tk.Frame(self.messages_frame, bg="white")
        system_frame.pack(fill='x', pady=2)

        # Create the message bubble
        bubble = tk.Frame(system_frame, bg="#d3d3d3", padx=10, pady=5, bd=1, relief='solid')
        bubble.pack(anchor='center', padx=10, pady=2)

        # System message label
        system_label = tk.Label(
            bubble,
            text=f"System [{timestamp}]: {message}",
            font=("Arial", 10, "italic"),
            fg='green',
            bg="#d3d3d3",
            wraplength=wrap_length,
            justify='center'
        )
        system_label.pack(anchor='center')

        # Auto-scroll to the bottom
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def send_message(self, event=None):
        message = self.message_var.get().strip()
        if message == "":
            return
        ciphertext = self.chat.send_encrypted(message)
        self.display_message(self.user_role, ciphertext, message)
        self.message_var.set("")

    def show_info(self):
        """Open the Info window rendered as HTML."""
        InfoWindow(self.root)

# Main Function
def main():
    # Initialize Tkinter Root and show Startup UI
    root = tk.Tk()
    startup_ui = StartupUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
