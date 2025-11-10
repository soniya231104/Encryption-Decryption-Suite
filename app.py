from flask import Flask, render_template, request, jsonify
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes as primitive_hashes
from cryptography.hazmat.backends import default_backend
import os
import secrets

app = Flask(__name__)

# ---------- Helpers ----------
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Derive a strong key from password using PBKDF2-HMAC-SHA256.
    Returns bytes of desired length (default 32 bytes).
    """
    kdf = PBKDF2HMAC(
        algorithm=primitive_hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ---------- AES (using AES-GCM) ----------
@app.route('/aes/encrypt', methods=['POST'])
def aes_encrypt():
    data = request.json or {}
    plaintext = (data.get('text') or "").encode()
    password = data.get('password') or ""
    if not plaintext:
        return jsonify({'ok': False, 'error': 'No text provided'}), 400
    if not password:
        return jsonify({'ok': False, 'error': 'Password required'}), 400

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt, 32)  # 256-bit key
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, None)

    # Return salt + nonce + ciphertext as base64
    payload = base64.urlsafe_b64encode(salt + nonce + ct).decode()
    return jsonify({'ok': True, 'result': payload})

@app.route('/aes/decrypt', methods=['POST'])
def aes_decrypt():
    data = request.json or {}
    payload_b64 = data.get('payload') or ""
    password = data.get('password') or ""
    if not payload_b64:
        return jsonify({'ok': False, 'error': 'No payload provided'}), 400
    if not password:
        return jsonify({'ok': False, 'error': 'Password required'}), 400
    try:
        payload = base64.urlsafe_b64decode(payload_b64)
        salt = payload[0:16]
        nonce = payload[16:28]
        ct = payload[28:]
        key = derive_key(password, salt, 32)
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return jsonify({'ok': True, 'result': pt.decode()})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Decryption failed: ' + str(e)}), 400

# ---------- RSA ----------
# We'll allow in-memory key generation per request (client can request generation)
@app.route('/rsa/generate', methods=['GET'])
def rsa_generate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return jsonify({'ok': True, 'public_key': pub_pem, 'private_key': priv_pem})

@app.route('/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json or {}
    text = (data.get('text') or "").encode()
    pub_pem = data.get('public_key') or ""
    if not text or not pub_pem:
        return jsonify({'ok': False, 'error': 'Text and public_key required'}), 400
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        ciphertext = pub.encrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=primitive_hashes.SHA256()),
                algorithm=primitive_hashes.SHA256(),
                label=None
            )
        )
        return jsonify({'ok': True, 'result': base64.urlsafe_b64encode(ciphertext).decode()})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Encryption failed: ' + str(e)}), 400

@app.route('/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json or {}
    payload_b64 = data.get('payload') or ""
    priv_pem = data.get('private_key') or ""
    if not payload_b64 or not priv_pem:
        return jsonify({'ok': False, 'error': 'payload and private_key required'}), 400
    try:
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None, backend=default_backend())
        ciphertext = base64.urlsafe_b64decode(payload_b64)
        plaintext = priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=primitive_hashes.SHA256()),
                algorithm=primitive_hashes.SHA256(),
                label=None
            )
        )
        return jsonify({'ok': True, 'result': plaintext.decode()})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Decryption failed: ' + str(e)}), 400

# ---------- Base64 ----------
@app.route('/base64/encode', methods=['POST'])
def base64_encode():
    text = (request.json.get('text') or "").encode()
    if not text:
        return jsonify({'ok': False, 'error': 'No text provided'}), 400
    return jsonify({'ok': True, 'result': base64.b64encode(text).decode()})

@app.route('/base64/decode', methods=['POST'])
def base64_decode():
    payload = request.json.get('payload') or ""
    if not payload:
        return jsonify({'ok': False, 'error': 'No payload provided'}), 400
    try:
        b = base64.b64decode(payload)
        return jsonify({'ok': True, 'result': b.decode()})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Decode failed: ' + str(e)}), 400

# ---------- Caesar Cipher ----------
def caesar_shift(text: str, shift: int):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)

@app.route('/caesar/encrypt', methods=['POST'])
def caesar_encrypt():
    text = request.json.get('text') or ""
    shift = int(request.json.get('shift') or 3)
    return jsonify({'ok': True, 'result': caesar_shift(text, shift)})

@app.route('/caesar/decrypt', methods=['POST'])
def caesar_decrypt():
    text = request.json.get('text') or ""
    shift = int(request.json.get('shift') or 3)
    return jsonify({'ok': True, 'result': caesar_shift(text, -shift)})

# ---------- Hash Generator ----------
@app.route('/hash/generate', methods=['POST'])
def hash_generate():
    text = (request.json.get('text') or "").encode()
    algo = (request.json.get('algorithm') or "SHA-256").upper()
    if not text:
        return jsonify({'ok': False, 'error': 'No text provided'}), 400

    try:
        if algo in ("SHA-256", "SHA256"):
            h = hashlib.sha256(text).hexdigest()
        elif algo in ("SHA-512", "SHA512"):
            h = hashlib.sha512(text).hexdigest()
        elif algo == "MD5":
            h = hashlib.md5(text).hexdigest()
        elif algo in ("SHA-1", "SHA1"):
            h = hashlib.sha1(text).hexdigest()
        else:
            return jsonify({'ok': False, 'error': 'Unsupported algorithm'}), 400
        return jsonify({'ok': True, 'result': h})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Hashing failed: ' + str(e)}), 400

# ---------- Frontend ----------
@app.route('/')
def index():
    return render_template('index.html')

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
