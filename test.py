import hashlib
import random
from math import log2

import base58
import ecdsa
from Crypto.Hash import SHA256, RIPEMD160


def generate_random_hex_between(min_hex, max_hex):
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


def generate_wif(private_key, compressed=False):
    """Generates a Bitcoin WIF (Wallet Import Format) for a given private key.

    Args:
        private_key: The private key as a 32-byte binary string.
        compressed: Whether to generate a compressed WIF (default: False).

    Returns:
        The Bitcoin WIF string.
    """

    # Add version byte (0x80 for mainnet)
    version = b'\x80'

    # Add compression flag if compressed
    if compressed:
        version += b'\x01'

    # Append private key
    data = version + private_key

    # Double SHA-256 hash
    first_hash = hashlib.sha256(data).digest()
    second_hash = hashlib.sha256(first_hash).digest()

    # Take the first 4 bytes of the second hash as the checksum
    checksum = second_hash[:4]

    # Combine data and checksum
    final_data = data + checksum

    # Base58 encode
    wif = base58.b58encode(final_data).decode('utf-8')

    return wif


def generate_btc_address_from_uncompressed_wif(private_key):
    """Generates a Bitcoin address from an uncompressed WIF.

    Args:
        wif: The Bitcoin WIF string (uncompressed).

    Returns:
        The Bitcoin address string.
    """

    fullkey = '80' + private_key.hex()
    sha256a = SHA256.new(bytes.fromhex(fullkey)).hexdigest()
    sha256b = SHA256.new(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8]))

    # Get public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Get compressed public key
    compressed_public_key = '02' if y % 2 == 0 else '03'
    compressed_public_key += x.to_bytes(32, 'big').hex()

    # Get P2PKH address
    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    return p2pkh_address


# Example usage
min_hex = "0000000000000000000000000000000000000000000000020000000000000000"  # Minimum hex value (red in RGB)
max_hex = "000000000000000000000000000000000000000000000003ffffffffffffffff"  # Maximum hex value (white in RGB)

print("Starting Scan Bitcoin 66")
random_hex = generate_random_hex_between(min_hex, max_hex)
print("Random HEX: ", random_hex)
# Convert hex string to binary data
private_key = bytes.fromhex(random_hex)
print("Private Key: ", private_key)
wif = generate_wif(private_key)
print("WIF: ", wif)
# wifc = generate_wif(private_key, True)
# print("WIF C: ", wifc)
btc_add = generate_btc_address_from_uncompressed_wif(private_key)
print(btc_add)
