import helper

def des_encrypt(plaintext_hex, key_hex):
    """Main encryption function - returns final ciphertext"""
    return des_encrypt_with_rounds(plaintext_hex, key_hex)[-1]

def des_decrypt(ciphertext_hex, key_hex):
    """Main decryption function - returns decrypted plaintext"""
    return des_decrypt_with_rounds(ciphertext_hex, key_hex)[-1]

def generate_round_keys(master_key_hex):
    """Generates all 16 round keys from master key"""
    # Permuted Choice 1 (PC1)
    PC1 = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    # Permuted Choice 2 (PC2)
    PC2 = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    master_key_bin = helper.hex_to_bin(master_key_hex)
    bits_56 = ''.join(master_key_bin[i-1] for i in PC1)
    left = bits_56[:28]
    right = bits_56[28:]
    keys = []
    for round in range(0, 16):
        left, right = key_schedule_shift(left, right, round) 
        combined = left + right
        keys.append(''.join(combined[i-1] for i in PC2))
    return keys

def key_schedule_shift(left_half, right_half, round_num):
    """Performs left shifts for key schedule"""
    # Key shift schedule (number of left shifts per round)
    KEY_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    shift_by =  KEY_SHIFT[round_num]
    left = left_half[shift_by:] + left_half[:shift_by]
    right = right_half[shift_by:] + right_half[:shift_by]
    return left, right

def feistel_function(right_half, round_key):
    """The core F function of DES"""
    expand = expansion_function(right_half)
    xor = helper.xor(expand, round_key)
    substitute = s_box_substitution(xor)
    permute = permutation_function(substitute)
    return permute

def expansion_function(bit_string):
    """Expands 32-bit input to 48-bit using E-table"""
    E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
    ]
    return ''.join(bit_string[i-1] for i in E)

def s_box_lookup(s_box_num, six_bits):
    """Looks up value in specific S-box (S1-S8)"""
    S_BOX = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    ]
    # calculate row from first and last bits
    row = int(six_bits[0] + six_bits[5], 2)
    # calculate column from middle 4 bits
    col = int(six_bits[1:5], 2)
    # look up value in S-box
    value = S_BOX[s_box_num][row][col]
    # convert to 4-bit binary string
    return format(value, '04b')

def s_box_substitution(bit_string):
    """Apply all 8 S-boxes to 48-bit input"""
    result = ""
    for i in range(8):
        six_bits = bit_string[i*6:(i+1)*6]
        result += s_box_lookup(i, six_bits)
    return result

def permutation_function(bit_string):
    """Applies P-box permutation to 32-bit input"""
    P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
    ]
    return ''.join(bit_string[i-1] for i in P)

def initial_permutation(bit_string):
    """Applies IP table to 64-bit input"""
    IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
    ]
    return ''.join(bit_string[i-1] for i in IP)

def final_permutation(bit_string):
    """Applies IP^-1 table to 64-bit input"""
    FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
    ]
    return ''.join(bit_string[i-1] for i in FP)

def permute(bit_string, permutation_table):
    """Generic permutation function used by all specific permutations"""
    return ''.join(bit_string[i-1] for i in permutation_table)

def spac_analysis(plaintext1_hex, plaintext2_hex, key_hex):
    """Performs SPAC analysis and returns round-by-round differences"""
    bit_difference_over_rounds = []
    results1 = des_encrypt_with_rounds(plaintext1_hex, key_hex)
    results2 = des_encrypt_with_rounds(plaintext2_hex, key_hex)
    for i in range(0, len(results1)):
        result1_bit = helper.hex_to_bin(results1[i])
        result2_bit = helper.hex_to_bin(results2[i])
        print(f"Round {i + 1}, {results1[i]}, {results2[i]}")
        bit_difference_over_rounds.append(calculate_bit_difference(result1_bit, result2_bit))
    return bit_difference_over_rounds

def skac_analysis(plaintext_hex, key1_hex, key2_hex):
    bit_difference_over_rounds = []
    results1 = des_encrypt_with_rounds(plaintext_hex, key1_hex)
    results2 = des_encrypt_with_rounds(plaintext_hex, key2_hex)
    for i in range(0, len(results1)):
        result1_bit = helper.hex_to_bin(results1[i])
        result2_bit = helper.hex_to_bin(results2[i])
        print(f"Round {i + 1}, {results1[i]}, {results2[i]}")
        bit_difference_over_rounds.append(calculate_bit_difference(result1_bit, result2_bit))
    return bit_difference_over_rounds

def calculate_bit_difference(bits1, bits2):
    """Calculates number of differing bits between two binary strings"""
    x = int(bits1, 16) ^ int(bits2, 16)
    return bin(x).count("1")

def des_encrypt_with_rounds(plaintext_hex, key_hex):
    # Convert to binary
    block = helper.hex_to_bin(plaintext_hex)
    
    # Generate round keys
    round_keys = generate_round_keys(key_hex)
    
    # Initial permutation
    block = initial_permutation(block)
    
    # Split into halves
    left, right = block[:32], block[32:]
    
    round_outputs = []
    
    # 16 rounds
    for round_num in range(16):
        # Feistel function
        feistel_output = feistel_function(right, round_keys[round_num])
        
        # XOR with left half
        new_right = helper.xor(left, feistel_output)
        
        # Update for next round (swap except last round)
        left, right = right, new_right
        
        # Get intermediate result (for analysis)
        if round_num < 15:
            combined = left + right
            round_outputs.append(helper.bin_to_hex(combined))
        else:
            combined = right + left  # No swap after last round  
            round_output = final_permutation(combined)    
            round_outputs.append(helper.bin_to_hex(round_output))
            
    
    return round_outputs

def des_decrypt_with_rounds(ciphertext_hex, key_hex):
    """Decryption that returns intermediate round results"""
    # Convert to binary
    block = helper.hex_to_bin(ciphertext_hex)

    # Generate round keys
    round_keys = generate_round_keys(key_hex)

    # Reverse for decryption
    reversed_round_keys = round_keys[::-1]
    
    # Initial permutation
    block = initial_permutation(block)
    
    # Split into halves
    left, right = block[:32], block[32:]
    
    round_outputs = []
    
    # 16 rounds
    for round_num in range(16):
        # Feistel function
        feistel_output = feistel_function(right, reversed_round_keys[round_num])
        
        # XOR with left half
        new_right = helper.xor(left, feistel_output)
        
        # Update for next round (swap except last round)
        left, right = right, new_right
        
        # Get intermediate result (for analysis)
        if round_num < 15:
            combined = left + right
            round_outputs.append(helper.bin_to_hex(combined))
        else:
            combined = right + left  # No swap after last round  
            round_output = final_permutation(combined)    
            round_outputs.append(helper.bin_to_hex(round_output))
            
    
    return round_outputs

def main():
    """Main function to test DES implementation"""
    print("=" * 60)
    print("DES IMPLEMENTATION TEST")
    print("=" * 60)
    
    # Test vectors from the assignment
    plaintext = "02468aceeca86420"
    key = "0f1571c947d9e859"
    expected_ciphertext = "da02ce3a89ecac3b"
    
    print(f"Plaintext:  {plaintext}")
    print(f"Key:        {key}")
    print(f"Expected:   {expected_ciphertext}")
    print("-" * 60)
    
    # Test 1: Basic Encryption
    print("\n1. BASIC ENCRYPTION TEST")
    print("-" * 40)
    
    ciphertext = des_encrypt(plaintext, key)
    print(f"Actual:     {ciphertext}")
    print(f"Encryption: {'PASS' if ciphertext.lower() == expected_ciphertext.lower() else 'FAIL'}")
    
    # Test 2: Round-by-Round Output (for Task 1 verification)
    print("\n2. ROUND-BY-ROUND OUTPUT (Task 1)")
    print("-" * 40)
    
    round_outputs = des_encrypt_with_rounds(plaintext, key)
    print("Round | Ciphertext")
    print("-" * 50)
    for i, output in enumerate(round_outputs, 1):
        print(f"{i:2d}    | {output}")
    
    # Test 3: Decryption Test
    print("\n3. DECRYPTION TEST")
    print("-" * 40)
    
    decrypted = des_decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted}")
    print(f"Decryption: {'PASS' if decrypted.lower() == plaintext.lower() else 'FAIL'}")
    
    # Test 4: SPAC Analysis (Task 2)
    print("\n4. SPAC ANALYSIS (Task 2)")
    print("-" * 40)
    
    # Create two plaintexts that differ by 1 bit
    plaintext1 = "02468aceeca86420"
    plaintext2 = "12468aceeca86420"
    
    print(f"Plaintext 1: {plaintext1}")
    print(f"Plaintext 2: {plaintext2}")
    
    spac_results = spac_analysis(plaintext1, plaintext2, key)
    print("\nSPAC Results (Differing bits per round):")
    for round_num, diff_bits in enumerate(spac_results, 1):
        print(f"Round {round_num:2d}: {diff_bits} bits differ")
    
    # Test 5: SKAC Analysis (Task 2)
    print("\n5. SKAC ANALYSIS (Task 2)")
    print("-" * 40)
    
    # Create two keys that differ by 1 bit
    key1 = "133457799BBCDFF1"
    key2 = flip_bit(key1, 0)  # Flip first bit
    
    print(f"Key 1: {key1}")
    print(f"Key 2: {key2}")
    
    skac_results = skac_analysis(plaintext1, key1, key2)
    print("\nSKAC Results (Differing bits per round):")
    for round_num, diff_bits in enumerate(skac_results, 1):
        print(f"Round {round_num:2d}: {diff_bits} bits differ")
    
    # Test 6: Quick verification with different test vector
    print("\n6. ADDITIONAL VERIFICATION")
    print("-" * 40)
    
    # Known test vector
    test_plaintext = "0123456789ABCDEF"
    test_key = "133457799BBCDFF1"
    known_ciphertext = "85E813540F0AB405"  # Known result
    
    result = des_encrypt(test_plaintext, test_key)
    print(f"Plaintext:  {test_plaintext}")
    print(f"Key:        {test_key}")
    print(f"Expected:   {known_ciphertext}")
    print(f"Actual:     {result}")
    print(f"Verification: {'PASS' if result.lower() == known_ciphertext.lower() else 'FAIL'}")
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETE")
    print("=" * 60)

# Helper function you'll need to implement
def flip_bit(hex_string, bit_position):
    """Flip a specific bit in a hex string"""
    # Convert to binary
    binary = helper.hex_to_bin(hex_string)
    # Flip the specified bit
    binary_list = list(binary)
    binary_list[bit_position] = '1' if binary_list[bit_position] == '0' else '0'
    # Convert back to hex
    return helper.bin_to_hex(''.join(binary_list))

if __name__ == "__main__":
    main()