def hex_to_bin(hex_string):
    """Convert hex string to binary string, preserving leading zeros"""
    # Convert each hex digit to 4-bit binary
    binary_chars = []
    for hex_char in hex_string:
        # Convert hex char to integer, then to 4-bit binary
        binary_char = format(int(hex_char, 16), '04b')
        binary_chars.append(binary_char)
    return ''.join(binary_chars)

def bin_to_hex(bit_string):
    """Convert binary string to hex string"""
    # Ensure length is multiple of 4
    if len(bit_string) % 4 != 0:
        # Pad with leading zeros if needed
        padding = 4 - (len(bit_string) % 4)
        bit_string = '0' * padding + bit_string
    
    hex_chars = []
    for i in range(0, len(bit_string), 4):
        # Take 4 bits at a time and convert to hex
        four_bits = bit_string[i:i+4]
        hex_char = format(int(four_bits, 2), 'X')
        hex_chars.append(hex_char)
    return ''.join(hex_chars)

def xor(bits1, bits2):
    """Bitwise XOR of two binary strings"""
    if len(bits1) != len(bits2):
        raise ValueError("Binary strings must be same length for XOR")
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))