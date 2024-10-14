import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import matplotlib.pyplot as plt

# BB84 Protocol: Generate a shared quantum key
BASIS = ['+', 'x']  # Two measurement bases: rectilinear (+) and diagonal (x)
BITS = [0, 1]       # The bits to be sent

def alice_manual_key_input(length):
    print(f"Please enter Alice's key (binary string of length {length}):")
    alice_key_str = input()
    
    while len(alice_key_str) != length or not set(alice_key_str).issubset({'0', '1'}):
        print(f"Invalid input! Please enter a binary string of length {length}:")
        alice_key_str = input()
    
    alice_bits = [int(bit) for bit in alice_key_str]
    alice_bases = np.random.choice(BASIS, size=length)
    return alice_bits, alice_bases

def measure_bits(bits, bases, measurement_bases):
    measured_bits = []
    for bit, basis, measurement_basis in zip(bits, bases, measurement_bases):
        if basis == measurement_basis:
            measured_bits.append(bit)
        else:
            measured_bits.append(np.random.choice(BITS))
    return measured_bits

def bb84_protocol_manual(length):
    alice_bits, alice_bases = alice_manual_key_input(length)
    bob_bases = np.random.choice(BASIS, size=length)
    bob_measured_bits = measure_bits(alice_bits, alice_bases, bob_bases)
    
    key = []
    for a_bit, a_basis, b_bit, b_basis in zip(alice_bits, alice_bases, bob_measured_bits, bob_bases):
        if a_basis == b_basis:
            key.append(a_bit)
    
    return key

# AES encryption and decryption using the shared key
def generate_aes_key(shared_key):
    key_str = ''.join(map(str, shared_key))
    hashed_key = hashlib.sha256(key_str.encode()).digest()
    return hashed_key

def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ciphertext

def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Attacker modifying the key
def attacker_modification(shared_key):
    print("Do you want to modify the key? (yes/no):")
    modify = input().strip().lower()

    if modify == 'yes':
        print(f"Shared key is: {shared_key}")
        print(f"Please enter the attacker's modified key (binary string of length {len(shared_key)}):")
        attacker_key_str = input()
        
        while len(attacker_key_str) != len(shared_key) or not set(attacker_key_str).issubset({'0', '1'}):
            print(f"Invalid input! Please enter a binary string of length {len(shared_key)}:")
            attacker_key_str = input()
        
        attacker_key = [int(bit) for bit in attacker_key_str]
        return attacker_key
    else:
        return shared_key  # No modification, the key stays the same

# Forensic analysis
def perform_forensic_analysis(original_key, attacker_key):
    discrepancies = 0
    for o_bit, a_bit in zip(original_key, attacker_key):
        if o_bit != a_bit:
            discrepancies += 1
    return discrepancies

# Function to run multiple rounds and track discrepancies
def run_multiple_rounds(rounds, key_length):
    discrepancies_list = []
    
    for round_number in range(rounds):
        print(f"\n--- Round {round_number + 1} ---")
        
        # Simulate the BB84 protocol with Alice manually inputting her key
        shared_key = bb84_protocol_manual(key_length)
        
        # Attacker modifies the key (if chosen)
        attacker_key = attacker_modification(shared_key)
        
        # Perform forensic analysis
        discrepancies = perform_forensic_analysis(shared_key, attacker_key)
        discrepancies_list.append(discrepancies)
        print(f"Discrepancies detected in Round {round_number + 1}: {discrepancies}")
    
    return discrepancies_list

# Visualization function
def visualize_discrepancies(discrepancies_list):
    rounds = list(range(1, len(discrepancies_list) + 1))
    
    plt.figure(figsize=(8, 6))
    plt.plot(rounds, discrepancies_list, marker='o', linestyle='-', color='b')
    plt.title("Forensic Analysis - Discrepancies Detected Over Multiple Rounds")
    plt.xlabel("Round Number")
    plt.ylabel("Number of Discrepancies Detected")
    plt.grid(True)
    plt.show()

# Main function to simulate the process with visualization
def main():
    rounds = 3  # Number of rounds for testing
    key_length = 10  # Key length

    # Run multiple rounds and track discrepancies
    discrepancies_list = run_multiple_rounds(rounds, key_length)
    
    # Visualize the discrepancies
    visualize_discrepancies(discrepancies_list)


if __name__ == "__main__":
    main()

