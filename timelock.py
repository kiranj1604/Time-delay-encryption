import json
import time
import argparse
import os
import sys
from tqdm import tqdm

# pycryptodome is required: pip install pycryptodome tqdm
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Constants ---
PRIME_BITS = 2048  # Bit length for the primes p and q. 2048 is reasonably secure.
AES_KEY_BYTES = 32 # Use a 256-bit AES key.
CALIBRATION_FILE = "calibration.json"

# --- Core Cryptographic and Puzzle Functions ---

def calibrate():
    """
    Benchmarks the machine to determine how many squarings it can perform per second.
    This helps in translating a desired time delay into the 't' parameter.
    """
    print("Calibrating machine performance. This will take about 10 seconds...")
    # Use a smaller modulus for calibration to speed things up without affecting the
    # core operation count too much.
    test_n = getPrime(1024) * getPrime(1024)
    g = 2
    
    start_time = time.time()
    iterations = 0
    duration = 10.0 # Calibrate for 10 seconds
    
    while (time.time() - start_time) < duration:
        g = pow(g, 2, test_n)
        iterations += 1
        
    iterations_per_second = int(iterations / duration)
    
    with open(CALIBRATION_FILE, "w") as f:
        json.dump({"iterations_per_second": iterations_per_second}, f)
        
    print(f"Calibration complete. Machine can perform approx. {iterations_per_second} squarings/sec.")
    print(f"Calibration data saved to '{CALIBRATION_FILE}'.")
    return iterations_per_second

def get_iterations_per_second():
    """Loads the calibration data. If not found, runs calibration."""
    if not os.path.exists(CALIBRATION_FILE):
        print("Calibration data not found.")
        return calibrate()
    with open(CALIBRATION_FILE, "r") as f:
        data = json.load(f)
        return data["iterations_per_second"]

def generate_puzzle(data_to_encrypt, delay_seconds):
    """
    Generates a time-lock puzzle and encrypts the data.
    
    Returns:
        tuple: (encrypted_data_package, puzzle_package)
    """
    # 1. Calibrate to determine 't'
    iterations_per_sec = get_iterations_per_second()
    t = delay_seconds * iterations_per_sec
    print(f"Targeting a delay of {delay_seconds}s, which requires t = {t} iterations.")

    # 2. Generate RSA modulus n, discarding p and q
    print(f"Generating {PRIME_BITS*2}-bit RSA modulus (n = p*q)...")
    p = getPrime(PRIME_BITS)
    q = getPrime(PRIME_BITS)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # 3. Generate a random AES key
    aes_key = get_random_bytes(AES_KEY_BYTES)
    
    # 4. Encrypt the data with AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)
    encrypted_data_package = {
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex()
    }
    
    # 5. Compute the puzzle result (the "shortcut" way)
    # The result is y = g^(2^t) mod n
    g = 2 # A common starting value
    exponent = pow(2, t, phi_n)
    puzzle_result_int = pow(g, exponent, n)

    # 6. Hide the AES key by XORing it with the puzzle result
    aes_key_int = bytes_to_long(aes_key)
    hidden_key_int = aes_key_int ^ puzzle_result_int
    
    puzzle_package = {
        "n": n,
        "t": t,
        "g": g,
        "hidden_key": hidden_key_int
    }
    
    return encrypted_data_package, puzzle_package

def solve_puzzle(puzzle_package, encrypted_data_package):
    """
    Solves the time-lock puzzle to find the AES key and decrypt the data.
    
    Returns:
        bytes: The original decrypted data.
    """
    # 1. Extract puzzle parameters
    n = puzzle_package["n"]
    t = puzzle_package["t"]
    g = puzzle_package["g"]
    hidden_key_int = puzzle_package["hidden_key"]

    # 2. Solve the puzzle by repeated squaring (the hard way)
    print(f"Solving puzzle... This will take a while (t = {t}).")
    current_value = g
    for _ in tqdm(range(t), desc="Solving Puzzle"):
        current_value = pow(current_value, 2, n)
    
    puzzle_result_int = current_value
    print("Puzzle solved!")

    # 3. Recover the AES key
    aes_key_int = hidden_key_int ^ puzzle_result_int
    aes_key = long_to_bytes(aes_key_int, AES_KEY_BYTES)
    
    # 4. Decrypt the data with the recovered key
    nonce = bytes.fromhex(encrypted_data_package["nonce"])
    ciphertext = bytes.fromhex(encrypted_data_package["ciphertext"])
    tag = bytes.fromhex(encrypted_data_package["tag"])
    
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        print("Decryption successful!")
        return decrypted_data
    except ValueError:
        print("Decryption failed. The key is incorrect or the data is corrupt.")
        return None

# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(
        description="Time-Lock Encryption Tool. Encrypts a file so it can only be decrypted after a certain time delay.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Calibrate command
    parser_calibrate = subparsers.add_parser("calibrate", help="Benchmark the machine to calibrate the time delay.")
    
    # Encrypt command
    parser_encrypt = subparsers.add_parser("encrypt", help="Encrypt a file with a time-lock.")
    parser_encrypt.add_argument("-i", "--input", required=True, help="Input file to encrypt.")
    parser_encrypt.add_argument("-d", "--delay", required=True, type=int, help="Desired time delay in seconds.")
    parser_encrypt.add_argument("-o", "--output", default="encrypted", help="Base name for output files (e.g., 'encrypted' -> encrypted.enc, encrypted.json).")

    # Decrypt command
    parser_decrypt = subparsers.add_parser("decrypt", help="Solve the puzzle and decrypt a file.")
    parser_decrypt.add_argument("-p", "--puzzle", required=True, help="Path to the puzzle JSON file.")
    parser_decrypt.add_argument("-i", "--input", required=True, help="Path to the encrypted data file (.enc).")
    parser_decrypt.add_argument("-o", "--output", required=True, help="Path to write the decrypted output file.")
    
    args = parser.parse_args()

    if args.command == "calibrate":
        calibrate()

    elif args.command == "encrypt":
        if not os.path.exists(args.input):
            print(f"Error: Input file not found at '{args.input}'")
            sys.exit(1)
        
        with open(args.input, "rb") as f:
            data_to_encrypt = f.read()

        encrypted_data_pkg, puzzle_pkg = generate_puzzle(data_to_encrypt, args.delay)
        
        # Save files
        enc_file_path = f"{args.output}.enc"
        puzzle_file_path = f"{args.output}.json"

        with open(enc_file_path, "w") as f:
            json.dump(encrypted_data_pkg, f, indent=2)
            
        # For the puzzle, n and hidden_key are large integers.
        # We need to handle them carefully for JSON serialization.
        puzzle_pkg_serializable = {k: str(v) for k, v in puzzle_pkg.items()}
        with open(puzzle_file_path, "w") as f:
            json.dump(puzzle_pkg_serializable, f, indent=2)

        print(f"\nEncryption complete!")
        print(f"Encrypted data saved to: {enc_file_path}")
        print(f"Puzzle file saved to:   {puzzle_file_path}")

    elif args.command == "decrypt":
        if not os.path.exists(args.puzzle) or not os.path.exists(args.input):
            print("Error: Puzzle or input file not found.")
            sys.exit(1)
            
        with open(args.puzzle, "r") as f:
            puzzle_pkg_str = json.load(f)
            # Convert string representations of large numbers back to integers
            puzzle_pkg = {k: int(v) for k, v in puzzle_pkg_str.items()}
            
        with open(args.input, "r") as f:
            encrypted_data_pkg = json.load(f)
            
        decrypted_data = solve_puzzle(puzzle_pkg, encrypted_data_pkg)
        
        if decrypted_data:
            with open(args.output, "wb") as f:
                f.write(decrypted_data)
            print(f"Decrypted file saved to: {args.output}")

if __name__ == "__main__":
    main()
