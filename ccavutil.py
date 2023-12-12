#!/usr/bin/env python

from crypto.Cipher import AES
from crypto.Random import get_random_bytes
import hashlib

def pad(data):
    length = 16 - (len(data) % 16)
    data += bytes([length]) * length
    return data

def encrypt(plainText, workingKey):
    iv = get_random_bytes(16)
    plainText = pad(plainText.encode())
    encDigest = hashlib.md5(workingKey.encode()).digest()
    enc_cipher = AES.new(encDigest, AES.MODE_CBC, iv)
    encryptedText = enc_cipher.encrypt(plainText)
    return iv.hex() + encryptedText.hex()

def decrypt(cipherText, workingKey):
    iv = bytes.fromhex(cipherText[:32])  # Extract IV from the first 16 bytes
    encryptedText = bytes.fromhex(cipherText[32:])  # Extract the ciphertext
    decDigest = hashlib.md5(workingKey.encode()).digest()
    dec_cipher = AES.new(decDigest, AES.MODE_CBC, iv)
    decryptedText = dec_cipher.decrypt(encryptedText).rstrip(bytes([encryptedText[-1]]))  # Remove padding
    return decryptedText.decode()

