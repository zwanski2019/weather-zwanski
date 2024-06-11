import argparse
import json
import logging
import sys
from base64 import b16decode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def decrypt_data(data, password):
    try:
        # Extract relevant values
        ciphertext = b16decode(data['crypto']['ciphertext'].upper())
        iv = b16decode(data['crypto']['cipherparams']['iv'].upper())
        salt = data['crypto']['kdfparams']['salt']

        # Check if the salt is empty and handle it
        if not salt:
            raise ValueError("Salt value is missing. Please provide the correct salt value.")
        
        salt = b16decode(salt.upper())
        dklen = data['crypto']['kdfparams']['dklen']
        n = data['crypto']['kdfparams']['n']
        p = data['crypto']['kdfparams']['p']
        r = data['crypto']['kdfparams']['r']

        # Derive the decryption key using scrypt
        kdf = Scrypt(
            salt=salt,
            length=dklen,
            n=n,
            r=r,
            p=p,
            backend=default_backend()
        )
        key = kdf.derive(password)

        # Verify MAC (Message Authentication Code)
        mac = b16decode(data['crypto']['mac'].upper())
        derived_mac = constant_time.bytes_eq(mac, key[:len(mac)])
        if not derived_mac:
            raise ValueError("MAC verification failed. The data may be corrupted or the password is incorrect.")

        # Decrypt the ciphertext
        cipher = Cipher(
            algorithms.AES(key[:16]),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode()

    except Exception as e:
        logging.error(f"An error occurred during decryption: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Decrypt encrypted data.')
    parser.add_argument('data', type=str, help='The JSON data to decrypt')
    parser.add_argument('password', type=str, help='The password to use for decryption')
    
    args = parser.parse_args()
    
    data = json.loads(args.data)
    password = args.password.encode()
    
    decrypted_data = decrypt_data(data, password)
    logging.info(f"Decrypted data: {decrypted_data}")

if __name__ == "__main__":
    main()
