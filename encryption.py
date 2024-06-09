from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Function to generate RSA key pairs and save them to files
def generate_and_save_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save private key to a file
    with open('private_key.pem', 'wb') as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key = private_key.public_key()

    # Save public key to a file
    with open('public_key.pem', 'wb') as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Function to encrypt data using the recipient's public key
def encrypt_with_public_key(public_key_file, plaintext):
    with open(public_key_file, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Function to decrypt data using the recipient's private key
def decrypt_with_private_key(private_key_file, ciphertext):
    with open(private_key_file, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

if __name__ == "__main__":
    generate_and_save_rsa_keys()

    plaintext = "This is a secret message."
    
    # Encrypt with the public key
    ciphertext = encrypt_with_public_key('public_key.pem', plaintext)
    
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt with the private key
    decrypted_text = decrypt_with_private_key('private_key.pem', ciphertext)
    
    print(f"Decrypted Text: {decrypted_text.decode()}")
