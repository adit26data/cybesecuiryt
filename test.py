import tkinter as tk
from tkinter import filedialog, messagebox

# Create main window
root = tk.Tk()
root.title("Cipher Encryption/Decryption Tool")
root.geometry("600x500")

# Define global variables
Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz' \
          '!@#$%&*(){}[]<>/\\|";:\n-=+.,?1234567890'

# Caesar Cipher Function
def caesar_cipher(message, key, mode='encrypt'):
    result = ""
    for char in message:
        if char in Letters:
            number = Letters.find(char)
            if mode == 'encrypt':
                number = number + int(key)
            else:
                number = number - int(key)
            if number >= len(Letters):
                number = number - len(Letters)
            elif number < 0:
                number = number + len(Letters)
            result += Letters[number]
        else:
            result += char
    return result

# Vigenère Cipher Function
def vigenere_cipher(message, key, mode='encrypt'):
    key = key.lower()
    result = ""
    key_index = 0

    for char in message:
        if char in Letters:
            char_index = Letters.find(char)
            key_char = key[key_index % len(key)]
            key_char_index = Letters.find(key_char)

            if mode == 'encrypt':
                new_index = (char_index + key_char_index) % len(Letters)
            else:
                new_index = (char_index - key_char_index) % len(Letters)

            result += Letters[new_index]
            key_index += 1
        else:
            result += char

    return result

# Playfair Cipher Function (basic version)
def generate_playfair_square(key):
    alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # J is omitted
    matrix = []
    used_letters = []

    key = key.upper().replace('J', 'I')  # Replace J with I in the key
    for char in key:
        if char not in used_letters and char in alphabet:
            matrix.append(char)
            used_letters.append(char)

    for char in alphabet:
        if char not in used_letters:
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def get_position(char, square):
    for row in range(5):
        for col in range(5):
            if square[row][col] == char:
                return row, col
    return None  # If the character is not found

def prepare_playfair_message(message):
    message = message.upper().replace('J', 'I')
    new_message = ""
    i = 0

    while i < len(message):
        char1 = message[i]
        if i + 1 < len(message):
            char2 = message[i + 1]
        else:
            char2 = 'X'

        if char1 == char2:
            new_message += char1 + 'X'
            i += 1
        else:
            new_message += char1 + char2
            i += 2

    if len(new_message) % 2 != 0:
        new_message += 'X'

    return new_message

def playfair_cipher(message, key, mode='encrypt'):
    square = generate_playfair_square(key)
    message = prepare_playfair_message(message)

    result = ""
    i = 0

    while i < len(message):
        char1 = message[i]

        # Check if char2 exists, otherwise set it as 'X'
        if i + 1 < len(message):
            char2 = message[i + 1]
        else:
            char2 = 'X'  # Handle odd-length messages by adding a filler

        if char1 not in 'ABCDEFGHIKLMNOPQRSTUVWXYZ' or char2 not in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
            # Skip non-alphabetic characters
            result += char1 if char1 in 'ABCDEFGHIKLMNOPQRSTUVWXYZ' else char2
            i += 1
            continue

        row1, col1 = get_position(char1, square)
        row2, col2 = get_position(char2, square)

        if row1 is None or row2 is None:
            i += 2  # Continue to the next pair of characters if positions not found
            continue

        if row1 == row2:
            if mode == 'encrypt':
                result += square[row1][(col1 + 1) % 5] + square[row2][(col2 + 1) % 5]
            else:
                result += square[row1][(col1 - 1) % 5] + square[row2][(col2 - 1) % 5]
        elif col1 == col2:
            if mode == 'encrypt':
                result += square[(row1 + 1) % 5][col1] + square[(row2 + 1) % 5][col2]
            else:
                result += square[(row1 - 1) % 5][col1] + square[(row2 - 1) % 5][col2]
        else:
            result += square[row1][col2] + square[row2][col1]

        i += 2

    return result

def process_message():
    cipher_type = cipher_var.get()
    mode = mode_var.get()
    key = key_entry.get()

    if not key:
        messagebox.showerror("Error", "Please enter a key.")
        return

    message = input_text.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Error", "Please enter a message to process.")
        return

    if cipher_type == "Caesar Cipher":
        if not key.isdigit() or int(key) <= 0 or int(key) > 90:
            messagebox.showerror("Error", "Please enter a valid key for Caesar (1-90).")
            return
        result = caesar_cipher(message, key, mode=mode.lower())
    elif cipher_type == "Vigenère Cipher":
        result = vigenere_cipher(message, key, mode=mode.lower())
    elif cipher_type == "Playfair Cipher":
        result = playfair_cipher(message, key, mode=mode.lower())

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                input_text.delete("1.0", tk.END)
                input_text.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {e}")

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, 'w') as file:
                file.write(output_text.get("1.0", tk.END).strip())
            messagebox.showinfo("Success", f"File saved successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving file: {e}")

# Labels and Buttons
intro_label = tk.Label(root, text="Cipher Encryption/Decryption Tool", font=("Helvetica", 16))
intro_label.pack(pady=10)

cipher_var = tk.StringVar(value="Caesar Cipher")
cipher_menu = tk.OptionMenu(root, cipher_var, "Caesar Cipher", "Vigenère Cipher", "Playfair Cipher")
cipher_menu.pack(pady=10)

mode_var = tk.StringVar(value="Encrypt")
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="Encrypt")
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="Decrypt")
encrypt_radio.pack()
decrypt_radio.pack()

key_label = tk.Label(root, text="Enter Key:")
key_label.pack(pady=5)
key_entry = tk.Entry(root)
key_entry.pack(pady=5)

input_text = tk.Text(root, height=5, width=50)
input_text.pack(pady=10)

file_button = tk.Button(root, text="Load from File", command=load_file)
file_button.pack(pady=5)

process_button = tk.Button(root, text="Process", command=process_message)
process_button.pack(pady=10)

output_text = tk.Text(root, height=5, width=50)
output_text.pack(pady=10)

save_button = tk.Button(root, text="Save to File", command=save_file)
save_button.pack(pady=5)

# Start the main loop
root.mainloop()
