# Decryptor

This script decrypts data encrypted with `aes-128-ctr` and key derived using the `scrypt` key derivation function. 

## Setup

Install the required dependencies:

```sh
pip install cryptography
```

## Usage

Update the `data` dictionary and `password` variable in the `decryptor.py` script with your data and password, then run the script:

```sh
python decryptor.py '{"activeAccounts": [{"address": "0xe4A23b422B21689ad394A525b54e7C1b052C80C5", "coin": 60, "derivationPath": "m/44'/60'/0'/0/0", "publicKey": "0469567c57e7f51b91c517a705d086061fa99f01b6a4fa08994a0b922ac6b1014f928c3a3b6c60f22d78d747c8214ae997f3e1c88588332eb07605295dba8d8491"}],"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"8a6c434354ce85a173afe1da2603c378"},"ciphertext":"4fb72645362329df2db066aa2f74bc47a42f2692c6b98c5842662ae94a761c42ba65b258a7e11ef1bd58da37a2b4e74b7c3627f28f450285b243e7c62afe8fd90e8594adf7bd83a2c4e9a8aa14e9","kdf":"scrypt","kdfparams":{"dklen":32,"n":16384,"p":4,"r":8,"salt":"YOUR_SALT_VALUE"},"mac":"5d0c565da42afb597eafa39fbfb49fc502b2b596472601f081fb3de1fac68bfd"},"id":"4dd6d157-0f0d-4412-aaf3-79912a3e1029","name":"","type":"mnemonic","version":3}' 'your_password'
```

## Logging

The script uses Python's logging module to log information and errors.

## Note

Ensure you provide the correct salt value for decryption to work. The script will exit with an error if the salt value is missing or incorrect.
