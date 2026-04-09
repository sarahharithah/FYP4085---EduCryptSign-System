from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import json
import hmac
import hashlib

class CryptoManager:
    """Handles all cryptographic operations"""
    
    @staticmethod
    def generate_key_pair():
        """Generate RSA key pair (2048-bit) - kept for compatibility"""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt_private_key(private_key, password):
        """Encrypt private key with user password"""
        password_bytes = password.encode('utf-8')
        key = SHA256.new(password_bytes).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(private_key)
        encrypted_data = {
            'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }
        return json.dumps(encrypted_data)
    
    @staticmethod
    def decrypt_private_key(encrypted_data, password):
        """Decrypt private key using password"""
        try:
            data = json.loads(encrypted_data)
            password_bytes = password.encode('utf-8')
            key = SHA256.new(password_bytes).digest()
            cipher = AES.new(key, AES.MODE_EAX, nonce=base64.b64decode(data['nonce']))
            private_key = cipher.decrypt_and_verify(
                base64.b64decode(data['ciphertext']),
                base64.b64decode(data['tag'])
            )
            return private_key
        except (ValueError, KeyError, TypeError):
            return None
    
    @staticmethod
    def sign_document(password, data):
        """Create HMAC signature using password as key"""
        try:
            key = password.encode('utf-8')
            message = data.encode('utf-8')
            signature = hmac.new(key, message, hashlib.sha256).digest()
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"Signing error: {e}")
            return None
    
    @staticmethod
    def verify_signature(password, data, signature):
        """Verify HMAC signature"""
        try:
            expected = CryptoManager.sign_document(password, data)
            if expected is None:
                return False
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            print(f"Verification error: {e}")
            return False