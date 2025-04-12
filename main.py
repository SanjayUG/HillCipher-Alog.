import numpy as np
import tkinter as tk
from tkinter import messagebox, ttk

def text_to_numbers(text):
    """Convert text to numerical representation (A=0, B=1, ..., Z=25)."""
    return [(ord(char) - ord('A')) for char in text.upper() if char.isalpha()]

def numbers_to_text(numbers):
    """Convert numerical values back to text representation."""
    return ''.join(chr(num + ord('A')) for num in numbers)

def mod_inverse_matrix(matrix, mod=26):
    """Compute the modular inverse of the matrix."""
    det = int(round(np.linalg.det(matrix)))
    try:
        det_inv = pow(det, -1, mod)  # Modular inverse of determinant
    except ValueError:
        raise ValueError("Matrix is not invertible (determinant has no modular inverse)")
    return (det_inv * np.round(np.linalg.inv(matrix) * det).astype(int)) % mod

def process_text(text, matrix_size):
    """Convert text to numbers and apply padding if necessary."""
    numbers = text_to_numbers(text)
    while len(numbers) % matrix_size:
        numbers.append(23)  # Padding with 'X'
    return numbers

def hill_cipher(text, key_matrix, encrypt=True):
    """Encrypt or decrypt text using the Hill Cipher."""
    n = len(key_matrix)
    numbers = process_text(text, n) if encrypt else text_to_numbers(text)

    matrix = key_matrix if encrypt else mod_inverse_matrix(key_matrix)
    processed_numbers = [
        (np.dot(matrix, numbers[i:i+n]) % 26).astype(int)
        for i in range(0, len(numbers), n)
    ]

    return numbers_to_text(np.concatenate(processed_numbers))

class HillCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hill Cipher Tool")
        self.root.geometry("600x500")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Input Frame
        input_frame = ttk.LabelFrame(self.root, text="Input", padding=10)
        input_frame.pack(pady=10, fill="x")
        
        ttk.Label(input_frame, text="Text:").grid(row=0, column=0, sticky="w")
        self.text_entry = ttk.Entry(input_frame, width=40)
        self.text_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Matrix Size (n):").grid(row=1, column=0, sticky="w")
        self.matrix_size = ttk.Combobox(input_frame, values=[2, 3, 4], width=5)
        self.matrix_size.set(2)
        self.matrix_size.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        # Key Matrix Frame
        self.matrix_frame = ttk.LabelFrame(self.root, text="Key Matrix", padding=10)
        self.matrix_frame.pack(pady=10, fill="x")
        self.create_matrix_input(2)  # Default to 2x2
        
        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        
        self.encrypt_btn = ttk.Button(button_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_btn.pack(side="left", padx=5)
        
        self.decrypt_btn = ttk.Button(button_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_btn.pack(side="left", padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="Clear", command=self.clear)
        self.clear_btn.pack(side="left", padx=5)
        
        # Output Frame
        output_frame = ttk.LabelFrame(self.root, text="Output", padding=10)
        output_frame.pack(pady=10, fill="both", expand=True)
        
        self.output_text = tk.Text(output_frame, height=8, wrap="word")
        self.output_text.pack(fill="both", expand=True)
        
        # Bind matrix size change
        self.matrix_size.bind("<<ComboboxSelected>>", self.update_matrix_input)
    
    def create_matrix_input(self, size):
        """Create entry widgets for matrix input based on size."""
        # Clear existing widgets
        for widget in self.matrix_frame.winfo_children():
            widget.destroy()
        
        self.matrix_entries = []
        for i in range(size):
            row_entries = []
            for j in range(size):
                entry = ttk.Entry(self.matrix_frame, width=5)
                entry.grid(row=i, column=j, padx=2, pady=2)
                row_entries.append(entry)
            self.matrix_entries.append(row_entries)
    
    def update_matrix_input(self, event=None):
        """Update matrix input when size changes."""
        try:
            size = int(self.matrix_size.get())
            self.create_matrix_input(size)
        except ValueError:
            pass
    
    def get_key_matrix(self):
        """Get the key matrix from input entries."""
        try:
            size = int(self.matrix_size.get())
            key_matrix = np.zeros((size, size), dtype=int)
            
            for i in range(size):
                for j in range(size):
                    value = self.matrix_entries[i][j].get()
                    if not value:
                        raise ValueError("All matrix elements must be filled")
                    key_matrix[i, j] = int(value)
            
            return key_matrix
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return None
    
    def encrypt(self):
        """Encrypt the input text."""
        text = self.text_entry.get()
        if not text:
            messagebox.showerror("Input Error", "Please enter text to encrypt")
            return
        
        key_matrix = self.get_key_matrix()
        if key_matrix is None:
            return
        
        try:
            ciphertext = hill_cipher(text, key_matrix, encrypt=True)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Ciphertext: {ciphertext}")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt(self):
        """Decrypt the input text."""
        text = self.text_entry.get()
        if not text:
            messagebox.showerror("Input Error", "Please enter text to decrypt")
            return
        
        key_matrix = self.get_key_matrix()
        if key_matrix is None:
            return
        
        try:
            plaintext = hill_cipher(text, key_matrix, encrypt=False)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Decrypted Text: {plaintext}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
    
    def clear(self):
        """Clear all inputs and outputs."""
        self.text_entry.delete(0, tk.END)
        self.output_text.delete(1.0, tk.END)
        size = int(self.matrix_size.get())
        for i in range(size):
            for j in range(size):
                self.matrix_entries[i][j].delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = HillCipherApp(root)
    root.mainloop()