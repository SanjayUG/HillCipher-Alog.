# Hill Cipher Implementation

A Python application that implements the Hill Cipher algorithm with a graphical user interface. This classical cryptographic technique uses matrices for encryption and decryption of text.

## Overview

The Hill Cipher is a polygraphic substitution cipher that operates on blocks of letters. It uses linear algebra and modular arithmetic to transform plaintext into ciphertext and vice versa. This implementation provides a user-friendly GUI built with Tkinter.

## Features

- Encrypt and decrypt text using the Hill Cipher algorithm
- Support for different matrix sizes (2×2, 3×3, and 4×4)
- Interactive GUI with input validation
- Real-time matrix size adjustment
- Automatic padding for incompatible text lengths

## Efficiency

The implementation leverages NumPy for matrix operations, providing:

- **Matrix Operations**: O(n³) complexity for matrix multiplication and inversion, where n is the matrix dimension
- **Text Processing**: O(m) complexity for processing text of length m
- **Space Efficiency**: Memory usage scales linearly with input text size
- **Vectorized Operations**: NumPy's optimized backend for faster matrix calculations

Performance characteristics:
- Small matrices (2×2, 3×3) process text almost instantaneously
- Larger matrices provide better security with minimal performance impact
- Memory footprint remains low even for large inputs

## Accuracy

The Hill Cipher implementation ensures mathematical accuracy through:

- **Modular Arithmetic**: All operations are performed modulo 26 (English alphabet)
- **Matrix Invertibility**: The system checks if the determinant has a modular inverse
- **Error Handling**: Proper validation for non-invertible matrices
- **Padding**: Automatic padding with 'X' (value 23) to ensure block size compatibility

The decryption process perfectly recovers the original plaintext when:
1. The key matrix is invertible in Z₂₆
2. The correct key matrix is provided
3. The text is properly formatted

## Usage

1. Enter the text to encrypt or decrypt in the input field
2. Select the matrix size from the dropdown (2, 3, or 4)
3. Fill in all elements of the key matrix with integer values
4. Click "Encrypt" or "Decrypt" button to process the text
5. View the result in the output area

## Requirements

- Python 3.x
- NumPy
- Tkinter (included in standard Python installation)

## Mathematical Background

The Hill Cipher operates on the following principles:

- **Encryption**: C = (KP) mod 26
- **Decryption**: P = (K⁻¹C) mod 26

Where:
- P is the plaintext block vector
- C is the ciphertext block vector
- K is the key matrix
- K⁻¹ is the modular inverse of the key matrix

The security of the cipher depends on the difficulty of determining the key matrix without knowing plaintext-ciphertext pairs.