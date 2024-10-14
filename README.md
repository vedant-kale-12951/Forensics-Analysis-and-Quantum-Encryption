**Project Overview**
This mini-project demonstrates the integration of quantum key distribution (QKD) using the BB84 protocol, classical encryption (AES), and basic forensic analysis to detect tampering during the key exchange process. The project simulates a scenario where two parties (Alice and Bob) exchange a key over a quantum channel, and a third party (Eve, the attacker) attempts to modify the key.

Forensic analysis is used to detect discrepancies in the shared key, and encryption/decryption is performed using the exchanged (or tampered) key. This mini-project helps illustrate some key challenges in quantum cryptography and forensics for encrypted communications.

**Key Features**
Quantum Key Distribution (BB84): Simulates a basic version of the BB84 protocol where Alice and Bob exchange keys. Alice can manually input her key, and Bob attempts to measure it.
Manual Key Modification by Attacker: After key distribution, an attacker can attempt to modify the shared key, simulating a man-in-the-middle attack.
Forensic Analysis: Detects discrepancies between Alice’s intended key and the attacker’s modified key.
AES Encryption/Decryption: Uses the final shared or tampered key to encrypt and decrypt a plaintext message, demonstrating the impact of key integrity on secure communication.

**How It Works?**
Alice’s Key Input: Alice manually inputs her binary key (e.g., "1101011101"), simulating quantum bit generation.
BB84 Key Distribution: Bob measures the quantum bits using randomly selected bases.
Attacker Modification: After key distribution, an attacker can modify the shared key by inputting a new key. If no attack occurs, the key remains unchanged.
Forensic Analysis: The system performs forensic analysis to detect any discrepancies between the original and modified keys.
Encryption & Decryption: The final key (either original or tampered) is used to encrypt and decrypt a confidential message using AES.

**Use Cases**
Successful Key Distribution: Alice and Bob successfully exchange a key without interference from an attacker.
Man-in-the-Middle Attack: An attacker modifies the key during distribution, and forensic analysis detects discrepancies.
Tampered Communication: An attacker modifies the ciphertext after encryption, demonstrating the effect of tampering on secure communication.

**Requirements**
Python 3.x
Required libraries:
numpy for key generation and random bases selection
pycryptodome for AES encryption and decryption
