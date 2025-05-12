from flask import Flask, request, jsonify
from flask import render_template

import numpy as np
import math

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

def text_to_numbers(text):
    return [ord(char) - ord('A') for char in text.upper() if char.isalpha()]

def numbers_to_text(numbers):
    return ''.join(chr(num + ord('A')) for num in numbers)

def check_invertibility(matrix, mod=26):
    det = int(np.round(np.linalg.det(matrix)))
    return math.gcd(det, mod) == 1

def mod_inverse_matrix(matrix, mod=26):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, mod)
    matrix_inv = np.round(det_inv * np.linalg.inv(matrix) * det).astype(int) % mod
    return matrix_inv

def encrypt(plaintext, key_matrix):
    n = len(key_matrix)
    plaintext_numbers = text_to_numbers(plaintext)

    while len(plaintext_numbers) % n != 0:
        plaintext_numbers.append(23)  # padding with 'X'

    ciphertext_numbers = []
    for i in range(0, len(plaintext_numbers), n):
        chunk = np.array(plaintext_numbers[i:i+n])
        encrypted_chunk = (np.dot(chunk, key_matrix) % 26).astype(int)
        ciphertext_numbers.extend(encrypted_chunk.tolist())

    return numbers_to_text(ciphertext_numbers)

def decrypt(ciphertext, key_matrix):
    inverse_key_matrix = mod_inverse_matrix(key_matrix)
    n = len(key_matrix)
    ciphertext_numbers = text_to_numbers(ciphertext)

    plaintext_numbers = []
    for i in range(0, len(ciphertext_numbers), n):
        chunk = np.array(ciphertext_numbers[i:i+n])
        decrypted_chunk = (np.dot(chunk, inverse_key_matrix) % 26).astype(int)
        plaintext_numbers.extend(decrypted_chunk.tolist())

    return numbers_to_text(plaintext_numbers)

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    data = request.json
    plaintext = data['plaintext']
    matrix = np.array(data['matrix'])
    
    if not check_invertibility(matrix):
        return jsonify({'error': 'Matrix not invertible'}), 400

    ciphertext = encrypt(plaintext, matrix)
    return jsonify({'ciphertext': ciphertext})

@app.route('/decrypt', methods=['POST'])
def decrypt_text():
    data = request.json
    ciphertext = data['ciphertext']
    matrix = np.array(data['matrix'])

    if not check_invertibility(matrix):
        return jsonify({'error': 'Matrix not invertible'}), 400

    plaintext = decrypt(ciphertext, matrix)
    return jsonify({'plaintext': plaintext})

if __name__ == '__main__':
    app.run(debug=True)
