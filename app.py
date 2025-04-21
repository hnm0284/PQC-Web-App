from flask import Flask, render_template, request, jsonify
from kyber_py.ml_kem import ML_KEM_512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64

# --- START OF SECURITY SETUP ---

from flask_talisman import Talisman
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create the Flask app
app = Flask(__name__)

# Use secret key from .env
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# Add security headers
Talisman(app)

# --- END OF SECURITY SETUP ---

# In-memory storage (temporary)
storedKeys = {
    "public": None,
    "private": None,
    "ciphertextKem": None,
    "encryptedMessage": None
}

# --- AES Utility Functions ---

def aesEncrypt(message: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    paddedMsg = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encryptedMsg = encryptor.update(paddedMsg) + encryptor.finalize()
    return iv + encryptedMsg

def aesDecrypt(ciphertext: bytes, key: bytes) -> str:
    iv = ciphertext[:16]
    encryptedMsg = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv))
    decryptor = cipher.decryptor()
    paddedMsg = decryptor.update(encryptedMsg) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(paddedMsg) + unpadder.finalize()
    return message.decode()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generateKeys():
    pubKey, privKey = ML_KEM_512.keygen()
    storedKeys['public'] = pubKey
    storedKeys['private'] = privKey
    return jsonify({
        'public_key': base64.b64encode(pubKey).decode(),
        'private_key': base64.b64encode(privKey).decode()
    })

@app.route('/encrypt', methods=['POST'])
def encryptMessage():
    message = request.form.get('message')
    
    # Check if the public key exists, if not, generate the keys first
    pubKey = storedKeys['public']
    if not pubKey:
        pubKey, privKey = ML_KEM_512.keygen()
        storedKeys['public'] = pubKey
        storedKeys['private'] = privKey
        
    sharedKey, ciphertextKem = ML_KEM_512.encaps(pubKey)
    encryptedMsg = aesEncrypt(message, sharedKey)
    storedKeys['ciphertextKem'] = ciphertextKem
    storedKeys['encryptedMessage'] = encryptedMsg
    return jsonify({
        'encrypted': base64.b64encode(encryptedMsg).decode()
    })

@app.route('/decrypt', methods=['POST'])
def decryptMessage():
    privKey = storedKeys['private']
    ciphertextKem = storedKeys['ciphertextKem']
    encryptedMsg = storedKeys['encryptedMessage']
    if not privKey or not ciphertextKem or not encryptedMsg:
        return jsonify({'error': 'Missing encryption data'}), 400
    sharedKey = ML_KEM_512.decaps(privKey, ciphertextKem)
    originalMsg = aesDecrypt(encryptedMsg, sharedKey)
    return jsonify({'decrypted': originalMsg})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))  # default to 10000 if not set
    app.run(host='0.0.0.0', port=port)
