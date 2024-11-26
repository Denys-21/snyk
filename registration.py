import tkinter as tk
from tkinter.filedialog import asksaveasfilename
import random
import string
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64
import sqlite3


def show_registration_page(root, back_callback):
    # Initialize database
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL
        )
    """)
    conn.commit()

    # Colors
    bg_color = "#0d1117"
    fg_color = "#c9d1d9"
    btn_bg_color = "#21262d"
    btn_hover_color = "#30363d"
    error_color = "red"

    # Clear previous widgets and configure background
    for widget in root.winfo_children():
        widget.destroy()
    root.configure(bg=bg_color)

    # Title
    title_label = tk.Label(root, text="Registration", font=("Arial", 24, "bold"), fg=fg_color, bg=bg_color)
    title_label.pack(pady=20)

    # Frames for input fields
    form_frame = tk.Frame(root, bg=bg_color)
    form_frame.pack(pady=10)

    # Username, First Name, Last Name
    fields = {}

    def create_labeled_entry(row, label_text):
        tk.Label(form_frame, text=label_text, font=("Arial", 14), fg=fg_color, bg=bg_color).grid(row=row, column=0, padx=5, pady=5, sticky="e")
        entry = tk.Entry(form_frame, width=30, font=("Arial", 12), bg="#161b22", fg=fg_color, insertbackground=fg_color)
        entry.grid(row=row, column=1, padx=5, pady=5)
        fields[label_text] = entry

    create_labeled_entry(0, "Username:")
    create_labeled_entry(1, "First Name:")
    create_labeled_entry(2, "Last Name:")
    create_labeled_entry(3, "Password:")
    fields["Password:"].config(show="*")
    create_labeled_entry(4, "Retype Password:")
    fields["Retype Password:"].config(show="*")

    # Status message label
    message_label = tk.Label(root, text="", font=("Arial", 14), fg="red", bg=bg_color)
    message_label.pack(pady=10)

    # Function to generate a random token
    def generate_token(length=75):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # Function to generate a random AES key
    def generate_aes_key(length=32):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # Function to encrypt the string
    def encrypt_data(data, key):
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=b'0000000000000000')
        encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(encrypted).decode()

    # Function to handle registration
    def register_user():
        # Check for empty fields
        empty_fields = []
        for label, entry in fields.items():
            if not entry.get():
                entry.config(highlightbackground=error_color, highlightcolor=error_color, highlightthickness=2)
                empty_fields.append(label)
            else:
                entry.config(highlightthickness=0)  # Reset border

        if empty_fields:
            message_label.config(text="Please fill in all fields!", fg=error_color)
            return

        # Collect data from fields
        login = fields["Username:"].get()
        firstname = fields["First Name:"].get()
        lastname = fields["Last Name:"].get()
        password = fields["Password:"].get()
        retype_password = fields["Retype Password:"].get()

        if password == retype_password:
            token = generate_token()
            combined_data = f"{login}/{firstname}/{lastname}/{password}/{token}"

            # Generate AES key and encrypt data
            aes_key = generate_aes_key()
            encrypted_data = encrypt_data(combined_data, aes_key)

            # Save AES key to file
            file_name = asksaveasfilename(
                initialfile="access_key.aask",
                defaultextension=".aask",
                filetypes=[("AES Key Files", "*.aask")],
                title="Save AES Key File"
            )
            if file_name:
                with open(file_name, "w") as file:
                    file.write(aes_key)

            # Insert encrypted data into database
            cursor.execute("INSERT INTO users (user) VALUES (?)", (encrypted_data,))
            conn.commit()

            message_label.config(text="Registration successful!", fg="green")
        else:
            fields["Password:"].config(highlightbackground=error_color, highlightcolor=error_color, highlightthickness=2)
            fields["Retype Password:"].config(highlightbackground=error_color, highlightcolor=error_color, highlightthickness=2)
            message_label.config(text="Passwords do not match!", fg=error_color)

    # Button frame
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=20)

    def create_button(text, command):
        btn = tk.Button(
            button_frame,
            text=text,
            command=command,
            font=("Arial", 12),
            bg=btn_bg_color,
            fg=fg_color,
            activebackground=btn_hover_color,
            activeforeground=fg_color,
            relief="flat",
            padx=20,
            pady=10,
            width=15
        )
        return btn

    register_button = create_button("Register", register_user)
    register_button.grid(row=0, column=0, padx=10)

    back_button = create_button("Back", lambda: back_callback(root))
    back_button.grid(row=0, column=1, padx=10)
