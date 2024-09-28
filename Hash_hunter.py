import hashlib
import sys
import binascii
from passlib.hash import nthash
import termcolor

import pyfiglet
from termcolor import colored


# Dictionary to map hash lengths to algorithms
hash_algorithms = {
    32: ["md5", "ntlm"],    # NTLM hashes are 32 characters long like MD5
    48: ["md4", "md2"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384"],
    128: ["sha512", "sha3_512"],
}

# Function to identify the hash algorithm based on length
def identify_hash(hash_value):
    hash_length = len(hash_value)
    
    if hash_length in hash_algorithms:
        possible_hashes = hash_algorithms[hash_length]
        print(f"Identified possible hash algorithms: {', '.join(possible_hashes)}")
        return possible_hashes
    else:
        print("Unknown hash type or unsupported hash length.")
        return []

# NTLM Hash Calculation using passlib
def ntlm_hash(word):
    """Generate NTLM hash for a given word using passlib"""
    return nthash.hash(word)

# Function to attempt cracking the hash using a wordlist
def crack_hash(hash_value, wordlist_file, hash_type):
    """Crack the hash using a wordlist"""
    try:
        with open(wordlist_file, 'r', encoding='utf-8') as wordlist:
            for word in wordlist:
                word = word.strip()

                if hash_type == 'ntlm':
                    hashed_word = ntlm_hash(word)
                else:
                    try:
                        # Calculate hash using hashlib
                        hash_obj = hashlib.new(hash_type.lower())  # Ensure lowercase
                        hash_obj.update(word.encode('utf-8'))
                        hashed_word = hash_obj.hexdigest()

                        # Debug: Print out hash for troubleshooting
                        #print(f"Word: {word}, Hashed: {hashed_word}, Target: {hash_value}")
                        
                    except ValueError as e:
                        print(f"Unsupported hash type: {hash_type}. Error: {e}")
                        return

                if hashed_word == hash_value:
                    print(f"Hash cracked! The original word is: {word}")
                    sys.exit(0)

        print(f"Failed to crack the {hash_type} hash using the wordlist.")
        sys.exit(1)
    except FileNotFoundError:
        print("Wordlist file not found. Please provide a valid path.")
        sys.exit(1)
    except UnicodeDecodeError:
        print("Error reading wordlist file. Ensure it is in UTF-8 encoding.")
        sys.exit(1)


def ntlm_hash(word):
    """Generate NTLM hash"""
    return hashlib.new('md4', word.encode('utf-16le')).hexdigest()


# Function to print available hashes
def print_supported_hashes():
    print(colored("\nSupported Hashes:", 'green'))
    print(colored("1. MD5", 'green'))
    print(colored("2. MD2", 'green'))
    print(colored("3. MD4", 'green'))
    print(colored("4. SHA-1", 'green'))
    print(colored("5. SHA-224", 'green'))
    print(colored("6. SHA-256", 'green'))
    print(colored("7. SHA-384", 'green'))
    print(colored("8. SHA-512", 'green'))
    print(colored("9. SHA3-256", 'green'))
    print(colored("10. SHA3-512", 'green'))
    print(colored("11. NTLM (Windows-based hashes)\n", 'green'))


# Display welcome_message_coloured
def display_welcome_message():
    # Create an ASCII art banner for the tool
    banner = pyfiglet.figlet_format("Hash Hunter", font="slant")
    colored_banner = colored(banner, 'cyan')

    
    print(colored_banner)
    print(colored("\n=== Welcome to the Hash Cracker ===", 'yellow'))
    print("This tool supports cracking a wide range of hashes using a wordlist.")
    print("It attempts to identify the hash and then crack it using the provided wordlist.")
    print("Ensure that your wordlist contains common passwords or words used for the hash.\n")
    
    print(colored("Use this tool responsibly.", 'red'))

# Function to ask user for input details
def get_user_input():
    hash_value = input("Enter the hash to crack: ").strip()
    wordlist_file = input("Enter the path to the wordlist file: ").strip()
    return hash_value, wordlist_file

# Main function to tie everything together
def main():
    # Display the welcome message and supported hashes
    display_welcome_message()
    print_supported_hashes()
    
    # Get user input
    hash_value, wordlist_file = get_user_input()

    # Step 1: Identify hash type
    possible_hashes = identify_hash(hash_value)

    if not possible_hashes:
        print("Unable to identify the hash. Exiting program.")
        return

    # Step 2: Try cracking the hash for each identified hash type
    for hash_type in possible_hashes:
        print(f"Trying to crack using {hash_type}...")
        crack_hash(hash_value, wordlist_file, hash_type)

    print("\n=== Hash Cracking Attempt Complete ===")

# Run the program
if __name__ == "__main__":
    main()
