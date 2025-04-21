from flask import Flask, render_template, request, jsonify
from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64


# --- START OF SECURITY SETUP ---

from flask_talisman import Talisman
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Create the Flask app
app = Flask(__name__)

# Use secret key from .env
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# Add security headers
Talisman(app)

# --- END OF SECURITY SETUP ---

app = Flask(__name__)

# In-memory storage (temporary)
stored_keys = {
    "public": None,
    "private": None,
    "ciphertext_kem": None,
    "encrypted_message": None
}

# --- AES Utility Functions ---

def aes_encrypt(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    #iv = b'1234567890abcdef'  # initialization vector
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(padded_msg) + encryptor.finalize()
    return iv + encrypted_msg

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    iv = ciphertext[:16]
    encrypted_msg = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(encrypted_msg) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_msg) + unpadder.finalize()
    return message.decode()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    pub_key, priv_key = ML_KEM_512.keygen()
    stored_keys['public'] = pub_key
    stored_keys['private'] = priv_key
    return jsonify({
        'public_key': base64.b64encode(pub_key).decode(),
        'private_key': base64.b64encode(priv_key).decode()
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form.get('message')
    
    # Check if the public key exists, if not, generate the keys first
    pub_key = stored_keys['public']
    if not pub_key:
        # Generate keys if not available
        pub_key, priv_key = ML_KEM_512.keygen()
        stored_keys['public'] = pub_key
        stored_keys['private'] = priv_key
        
    shared_key, ciphertext_kem = ML_KEM_512.encaps(pub_key)
    encrypted_msg = aes_encrypt(message, shared_key)
    stored_keys['ciphertext_kem'] = ciphertext_kem
    stored_keys['encrypted_message'] = encrypted_msg
    return jsonify({
        'encrypted': base64.b64encode(encrypted_msg).decode()
    })


@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    priv_key = stored_keys['private']
    ciphertext_kem = stored_keys['ciphertext_kem']
    encrypted_msg = stored_keys['encrypted_message']
    if not priv_key or not ciphertext_kem or not encrypted_msg:
        return jsonify({'error': 'Missing encryption data'}), 400
    shared_key = ML_KEM_512.decaps(priv_key, ciphertext_kem)
    original_msg = aes_decrypt(encrypted_msg, shared_key)
    return jsonify({'decrypted': original_msg})

if __name__ == '__main__':
    app.run(debug=True)
