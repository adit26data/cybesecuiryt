import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar
import string
from itertools import product
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Define the character set used in encryption/decryption
Letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz' \
          '!@#$%&*(){}[]<>/\\|";:\n-=+.,?1234567890'

# Load a simple word dictionary (for word validation)
with open("words.txt", "r") as word_file:
    english_words = set(word.strip().lower() for word in word_file.readlines())

def caesar_decrypt(ciphertext, key):
    decrypted_text = ""
    for char in ciphertext:
        if char in Letters:
            number = Letters.find(char)
            number = (number - key) % len(Letters)
            decrypted_text += Letters[number]
        else:
            decrypted_text += char
    return decrypted_text

def vigenere_decrypt(ciphertext, key):
    result = ""
    key = key.lower()
    key_index = 0
    for char in ciphertext:
        if char in Letters:
            char_index = Letters.find(char)
            key_char = key[key_index % len(key)]
            key_char_index = Letters.find(key_char)

            new_index = (char_index - key_char_index) % len(Letters)
            result += Letters[new_index]
            key_index += 1
        else:
            result += char
    return result

def create_playfair_matrix(key):
    key = key.replace('j', 'i')
    key = ''.join(sorted(set(key), key=lambda x: key.index(x)))
    alphabet = 'abcdefghiklmnopqrstuvwxyz'
    matrix = list(key)

    for char in alphabet:
        if char not in matrix:
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    decrypted_text = ""
    flat_matrix = [char for row in matrix for char in row]
    
    ciphertext = ciphertext.replace(" ", "").lower()
    if len(ciphertext) % 2 != 0:
        ciphertext += 'x'

    pairs = [ciphertext[i:i + 2] for i in range(0, len(ciphertext), 2)]
    for a, b in pairs:
        if a not in flat_matrix or b not in flat_matrix:
            decrypted_text += a + b
            continue

        row_a, col_a = divmod(flat_matrix.index(a), 5)
        row_b, col_b = divmod(flat_matrix.index(b), 5)

        if row_a == row_b:
            decrypted_text += flat_matrix[row_a * 5 + (col_a - 1) % 5]
            decrypted_text += flat_matrix[row_b * 5 + (col_b - 1) % 5]
        elif col_a == col_b:
            decrypted_text += flat_matrix[((row_a - 1) % 5) * 5 + col_a]
            decrypted_text += flat_matrix[((row_b - 1) % 5) * 5 + col_b]
        else:
            decrypted_text += flat_matrix[row_a * 5 + col_b]
            decrypted_text += flat_matrix[row_b * 5 + col_a]

    return decrypted_text

def count_valid_words(text, dictionary):
    words = text.lower().split()
    valid_word_count = sum(1 for word in words if word in dictionary)
    return valid_word_count

class CipherDecryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Decryption Tool")
        
        # Create GUI elements
        self.label = tk.Label(root, text="Cipher Brute-force Decryption", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.open_button = tk.Button(root, text="Open Encrypted File", command=self.open_file)
        self.open_button.pack(pady=10)

        self.decrypt_button = tk.Button(root, text="Brute-force Decrypt", command=self.start_decryption, state=tk.DISABLED)
        self.decrypt_button.pack(pady=10)

        self.progress = Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10)

        self.result_text = tk.Text(root, height=15, width=60)
        self.result_text.pack(pady=10)

        self.best_key_label = tk.Label(root, text="Best Decryption Key: ")
        self.best_key_label.pack(pady=10)

        self.file_content = None

    def open_file(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.file_content = file.read()
                messagebox.showinfo("Success", "File Loaded Successfully!")
                self.decrypt_button.config(state=tk.NORMAL)
            except Exception as e:
                messagebox.showerror("Error", f"Error loading file: {e}")
                self.decrypt_button.config(state=tk.DISABLED)

    def start_decryption(self):
        # Start the decryption process in a separate thread
        threading.Thread(target=self.brute_force_attack, daemon=True).start()

    def brute_force_attack(self):
        if not self.file_content:
            messagebox.showerror("Error", "Please load a file first!")
            return

        self.result_text.delete(1.0, tk.END)  # Clear previous results
        self.progress["value"] = 0  # Reset progress bar

        best_key = None
        best_decryption = None
        best_valid_word_count = 0
        best_cipher_type = None
        total_attempts = 0

        with ThreadPoolExecutor() as executor:
            future_results = []

            # Count total attempts for progress bar
            for key in range(1, 91):
                total_attempts += 1

            # Try Vigenère Cipher brute-force with limited length
            for length in range(1, 4):
                total_attempts += len(list(product(string.ascii_lowercase, repeat=length)))

            # Try Playfair Cipher brute-force with limited length
            for length in range(1, 4):
                total_attempts += len(list(product(string.ascii_lowercase, repeat=length)))

            self.progress["maximum"] = total_attempts
            
            # Try Caesar Cipher brute-force
            for key in range(1, 91):
                future = executor.submit(self.decrypt_caesar, key)
                future_results.append(future)

            # Try Vigenère Cipher brute-force
            for length in range(1, 4):
                for key in self.generate_all_keys(length):
                    future = executor.submit(self.decrypt_vigenere, key)
                    future_results.append(future)

            # Try Playfair Cipher brute-force
            for length in range(1, 4):
                for key in self.generate_all_keys(length):
                    future = executor.submit(self.decrypt_playfair, key)
                    future_results.append(future)

            # Process results as they complete
            for i, future in enumerate(as_completed(future_results)):
                result = future.result()
                self.progress["value"] = i + 1  # Update progress bar
                self.root.update_idletasks()  # Refresh the GUI

                if result and result[1] > best_valid_word_count:
                    best_valid_word_count, best_decryption, best_key, best_cipher_type = result[1], result[0], result[2], result[3]

        # Once all decryption attempts are done, show the best result
        if best_key:
            self.result_text.insert(tk.END, f"Decrypted Text ({best_cipher_type}, Key = {best_key}):\n\n{best_decryption}")
            self.best_key_label.config(text=f"Best Decryption Key: {best_key} (Cipher: {best_cipher_type})")
        else:
            messagebox.showinfo("No Result", "No valid decryption found.")

    def decrypt_caesar(self, key):
        decrypted_text = caesar_decrypt(self.file_content, key)
        valid_word_count = count_valid_words(decrypted_text, english_words)
        return decrypted_text, valid_word_count, key, "Caesar Cipher"

    def decrypt_vigenere(self, key):
        decrypted_text = vigenere_decrypt(self.file_content, key)
        valid_word_count = count_valid_words(decrypted_text, english_words)
        return decrypted_text, valid_word_count, key, "Vigenère Cipher"

    def decrypt_playfair(self, key):
        decrypted_text = playfair_decrypt(self.file_content, key)
        valid_word_count = count_valid_words(decrypted_text, english_words)
        return decrypted_text, valid_word_count, key, "Playfair Cipher"

    def generate_all_keys(self, length):
        """Generates all possible keys of the given length using letters a-z."""
        letters = string.ascii_lowercase
        return (''.join(p) for p in product(letters, repeat=length))

# Initialize and run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = CipherDecryptionApp(root)
    root.mainloop()
