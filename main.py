import hashlib
import time
import base58
import ecdsa
import numpy as np
import requests
import random
from math import log2


def generate_private_key():
    min_hex = "0000000000000000000000000000000000000000000000020000000000000000"  # Minimum hex value (red in RGB)
    max_hex = "000000000000000000000000000000000000000000000003ffffffffffffffff"  # Maximum hex value (white in RGB)
    if int(min_hex, 16) > int(max_hex, 16):
        raise ValueError("min_hex must be less than or equal to max_hex")

    # Convert hex strings to integers
    min_value = int(min_hex, 16)
    max_value = int(max_hex, 16)

    # Calculate the number of bits needed to represent the range
    num_bits = int(log2(max_value - min_value + 1))

    # Generate a random integer within the range
    random_int = random.randint(0, 2 ** num_bits - 1)

    # Add the minimum value to get the final random value
    random_value = min_value + random_int

    # Convert the random value back to a hex string
    random_hex = hex(random_value)[2:]

    # Ensure consistent length by padding with zeros
    random_hex = random_hex.zfill(len(max_hex))

    return random_hex


def private_key_to_WIF(private_key_hex):
    # Add prefix byte 0x80 to indicate a Bitcoin private key
    prefix_and_key = "80" + private_key_hex

    # Calculate the double-SHA256 hash of the prefix and key
    hash_bytes = hashlib.sha256(hashlib.sha256(bytes.fromhex(prefix_and_key)).digest()).digest()

    # Take the first 4 bytes of the hash as the checksum
    checksum = hash_bytes[:4].hex()

    # Add the checksum to the end of the prefix and key
    prefix_key_checksum = prefix_and_key + checksum

    # Encode the result in base58
    wif_private_key = base58.b58encode(bytes.fromhex(prefix_key_checksum)).decode('utf-8')

    return wif_private_key


def private_key_to_public_key(private_key_hex):
    # Convert the private key from hexadecimal to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Create an ECDSA SECP256k1 curve object
    curve = ecdsa.curves.SECP256k1

    # Create a signing key from the private key bytes
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=curve)

    # Get the verifying key (public key) from the signing key
    verifying_key = signing_key.get_verifying_key()

    # Convert the public key to uncompressed format and then to hexadecimal
    public_key_bytes = b"\x04" + verifying_key.to_string()
    public_key_hex = public_key_bytes.hex()

    return public_key_hex


def public_key_to_address(public_key_hex):
    # Convert the public key from hexadecimal to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Apply SHA-256 to the public key
    hash1 = hashlib.sha256(public_key_bytes).digest()

    # Apply RIPEMD-160 to the SHA-256 hash
    hash2 = hashlib.new('ripemd160', hash1).digest()

    # Add prefix byte 0x00 to indicate a Bitcoin address
    prefix_and_hash = "00" + hash2.hex()

    # Calculate the double-SHA256 hash of the prefix and hash
    hash_bytes = hashlib.sha256(hashlib.sha256(bytes.fromhex(prefix_and_hash)).digest()).digest()

    # Take the first 4 bytes of the hash as the checksum
    checksum = hash_bytes[:4].hex()

    # Add the checksum to the end of the prefix and hash
    prefix_hash_checksum = prefix_and_hash + checksum

    # Encode the result in base58
    address = base58.b58encode(bytes.fromhex(prefix_hash_checksum)).decode('utf-8')

    return address


n = 10000
arr = np.empty((n, 2), dtype=object)

for i in range(n):
    private_key_hex = generate_private_key()
    wif_private_key = private_key_to_WIF(private_key_hex)
    public_key_hex = private_key_to_public_key(private_key_hex)
    address = public_key_to_address(public_key_hex)
    arr[i, 0] = wif_private_key
    arr[i, 1] = address

print(arr)


def check_balance(addr):
    adddrs_index = {}
    adddrs = ''
    for i in range(len(addr)):
        adddrs = adddrs + addr[i, 1] + '|'
        adddrs_index[addr[i, 1]] = addr[i, 0]
    url = f"https://blockchain.info/balance/?active={adddrs}"
    response = requests.get(url)
    if response.status_code == 200:
        for key, value in response.json().items():
            if (int(value['final_balance']) > 0 or int(value['n_tx']) > 0):
                record_wallet("non_zero_balances.txt", f"{adddrs_index[key]},{key},{value['final_balance']}\n")
        return 0
    else:
        print(f"Error {response.status_code}: {response.reason}")
        return None


def record_wallet(file_path, new_line):
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        lines.append(new_line)

        with open(file_path, 'w') as f:
            f.writelines(lines)

    except FileNotFoundError:
        print(f"File '{file_path}' not found.")


def process_list(my_list):
    for i in range(0, len(my_list), 50):
        process_list_chunk = my_list[i:i + 50]
        # process_list_chunk[0][1]='16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf'
        check_balance(process_list_chunk)
        time.sleep(30)


process_list(arr)
