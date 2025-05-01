import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import time

# Crypto Settings
KEY_LENGTH = 16  # 128 bits
SALT = b'secure_chat_salt'  # In real world, use random salt and exchange
KEY_REFRESH_INTERVAL = 300  # 5 minutes

# Padding for AES
def pad(msg):
    padding_len = AES.block_size - len(msg) % AES.block_size
    return msg + bytes([padding_len] * padding_len)

def unpad(msg):
    padding_len = msg[-1]
    return msg[:-padding_len]

# Key Derivation
def derive_key(password):
    return PBKDF2(password, SALT, dkLen=KEY_LENGTH)

class SecureChatClient:
    def __init__(self, master, is_server, host, port, password):
        self.master = master
        self.is_server = is_server
        self.host = host
        self.port = port
        self.password = password
        self.key = derive_key(password)
        self.last_key_update = time.time()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.is_server:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            self.conn, _ = self.sock.accept()
        else:
            self.sock.connect((self.host, self.port))
            self.conn = self.sock

        self.gui_done = False
        self.running = True

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive_loop)
        gui_thread.start()
        receive_thread.start()

    def encrypt_message(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        if time.time() - self.last_key_update > KEY_REFRESH_INTERVAL:
            self.update_key()

        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext))
        return base64.b64encode(iv + ciphertext).decode()

    def decrypt_message(self, enc_message):
        raw = base64.b64decode(enc_message)
        iv = raw[:AES.block_size]
        ciphertext = raw[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))
        return plaintext.decode()

    def update_key(self):
        self.key = derive_key(self.password + str(int(time.time() // KEY_REFRESH_INTERVAL)))
        self.last_key_update = time.time()

    def gui_loop(self):
        self.master.title("Secure Chat")

        self.chat_label = tk.Label(self.master, text="Secure Chat")
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = scrolledtext.ScrolledText(self.master)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')

        self.msg_entry = tk.Entry(self.master)
        self.msg_entry.pack(padx=20, pady=5)
        self.msg_entry.bind("<Return>", self.write)

        self.send_button = tk.Button(self.master, text="Send", command=self.write)
        self.send_button.pack(padx=20, pady=5)

        self.gui_done = True

        self.master.protocol("WM_DELETE_WINDOW", self.stop)

    def write(self, event=None):
        message = self.msg_entry.get()
        self.msg_entry.delete(0, tk.END)
        enc_message = self.encrypt_message(message)
        self.conn.send(enc_message.encode())

        if self.gui_done:
            self.text_area.config(state='normal')
            self.text_area.insert('end', f"You (ciphertext): {enc_message}\n")
            self.text_area.insert('end', f"You (plaintext): {message}\n")
            self.text_area.yview('end')
            self.text_area.config(state='disabled')

    def receive_loop(self):
        while self.running:
            try:
                message = self.conn.recv(1024).decode()
                if message:
                    plaintext = self.decrypt_message(message)
                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', f"Friend (ciphertext): {message}\n")
                        self.text_area.insert('end', f"Friend (plaintext): {plaintext}\n")
                        self.text_area.yview('end')
                        self.text_area.config(state='disabled')
            except ConnectionAbortedError:
                break
            except Exception as e:
                print("Error:", e)
                self.stop()
                break

    def stop(self):
        self.running = False
        self.master.destroy()
        self.conn.close()
        self.sock.close()
        exit(0)

# Set up the program
if __name__ == "__main__":
    root = tk.Tk()
    is_server = simpledialog.askstring("Role", "Are you the server? (yes/no)").lower() == "yes"
    host = simpledialog.askstring("Host", "Enter host (leave blank for localhost)")
    if not host:
        host = '127.0.0.1'
    port = int(simpledialog.askstring("Port", "Enter port"))
    password = simpledialog.askstring("Password", "Enter shared password (passphrase)")

    client = SecureChatClient(root, is_server, host, port, password)
    root.mainloop()
