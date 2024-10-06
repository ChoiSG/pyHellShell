import os
import sys
import uuid
import argparse 
from typing import Iterator
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
# OBFUSCATION Methods 
"""
def ipv6fuscation(file_data):
    ipv6Strings = []

    # Padding 
    remainder = len(file_data) % 16
    if remainder != 0:
        padding_length = 16 - remainder
        file_data += b'\x00' * padding_length

    # Actually using standard IPv6 notation
    for i in range(0, len(file_data), 16):
        bytes_chunk = file_data[i:i+16]
        words = [bytes_chunk[j] << 8 | bytes_chunk[j+1] for j in range(0, 16, 2)]
        ipv6Strings.append(':'.join('{:04x}'.format(w) for w in words))

    return ipv6Strings



def ipv4fuscation(file_data): 
    ipv4Strings = []

    # Pad 4 bytes for ipv4
    remainder = len(file_data) % 4
    if remainder != 0:
        file_data += b'\x00' * (4 - remainder)

    # Convert to ipv6 
    for i in range(0, len(file_data), 4):
        ipv4Strings.append('.'.join(str(b) for b in file_data[i:i+4]))

    return ipv4Strings

def macfuscation(file_data):
    macStrings = []

    # Pad 6 bytes for mac addr 
    remainder = len(file_data) % 6
    if remainder != 0:
        file_data += b'\x00' * (6 - remainder)

    # Convert to ipv6 
    for i in range(0, len(file_data), 6):
        macStrings.append(':'.join('{:02x}'.format(b) for b in file_data[i:i+6]))

    return macStrings

def uuidfuscation(file_data):
    uuidStrings = []

    # Pad 16 bytes for UUID
    remainder = len(file_data) % 16
    if remainder != 0:
        file_data += b'\x00' * (16 - remainder)

    # Convert to UUID
    for i in range(0, len(file_data), 16):
        chunk = file_data[i:i+16]

        first_segment = chunk[0:4]
        second_segment = chunk[4:6]
        third_segment = chunk[6:8]
        fourth_segment = chunk[8:10]
        fifth_segment = chunk[10:16]

        # little endian (4 bytes "-" 2 bytes "-" 2bytes) 
        # big endiance (2 bytes "-" 6bytes)
        reordered_chunk = first_segment[::-1] + second_segment[::-1] + third_segment[::-1] + fourth_segment + fifth_segment
        formatted_uuid = uuid.UUID(bytes=reordered_chunk)
        uuidStrings.append(formatted_uuid)

    return uuidStrings

"""
# ENCRYPTION methods 
"""

def XOR(data, key):
    key = key.encode('utf-8')
    key_len = len(key)
    print(f"key: {key}")
    print(f"key length: {key_len}")
    result = bytearray(data)
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % key_len]
    return result

# def xor(file_data, key):

#     encrypted_data = b''
#     for b in range(len(file_data)):
#         each_byte = file_data[b] ^ ord(key[b % len(key)])
#         encrypted_data += bytes([each_byte])

#     return encrypted_data


# SystemFunction032 Encrypt/Decrypt Functions 
# Yoinked from: https://gist.github.com/hsauers5/491f9dde975f1eaa97103427eda50071
def key_scheduling(key: bytes) -> list[int]:
    sched = [i for i in range(0, 256)]

    i = 0
    for j in range(0, 256):
        i = (i + sched[j] + key[j % len(key)]) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp

    return sched


def stream_generation(sched: list[int]) -> Iterator[bytes]:
    i, j = 0, 0
    while True:
        i = (1 + i) % 256
        j = (sched[i] + j) % 256
        tmp = sched[j]
        sched[j] = sched[i]
        sched[i] = tmp
        yield sched[(sched[i] + sched[j]) % 256]        


def rc4(plaintext: bytes, key: bytes) -> bytes:
    sched = key_scheduling(key)
    key_stream = stream_generation(sched)
    
    ciphertext = b''
    for char in plaintext:
        enc = char ^ next(key_stream)
        ciphertext += bytes([enc])
        
    return ciphertext

def aes256_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        print("[-] AES256 Key must be 32 bytes.")
        sys.exit(1)

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Create the cipher object and encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Setting global var IV - ik it's bad 
    global aes_IV 
    aes_IV = iv

    return iv + ciphertext  # Prepend the IV to the ciphertext


"""
# OUTPUT methods
"""

def outputCArray(obfuscatedString, method):
    if method == "ipv4":
        spacing = 8
    elif method == "ipv6":
        spacing = 2
    elif method == "mac":
        spacing = 6
    elif method == "uuid":
        spacing = 4
    else:
        spacing = 8

    outputString = "" 
    outputString += "const char* buf[] = {\n"
    for i in range(0, len(obfuscatedString), spacing):
        outputString += "\t"

        for j in range(0, spacing):
            if i + j < len(obfuscatedString):
                if i + j != len(obfuscatedString) - 1:
                    outputString += f'"{obfuscatedString[i+j]}", '
                else:
                    outputString += f'"{obfuscatedString[i+j]}"'
        
        outputString += "\n"
    
    outputString += "};\n"
    return outputString

def saveRawToFile(data, outputFilePath, obs_or_enc="obfuscated"):
    try: 
        if obs_or_enc == "obfuscated":
            with open(outputFilePath, "w") as file:
                for i in range(0, len(data)):
                    if i != len(data) - 1:
                        file.write(f"{data[i]},")
                    else:
                        file.write(f"{data[i]}") 
            return True
        
        elif obs_or_enc == "encrypted": 
            with open(outputFilePath, "wb") as file:
                file.write(data)
            return True
        
        else:
            print("[-] Invalid argument for obs_or_enc.")
            return False
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


def argparser():
    parser = argparse.ArgumentParser(description="pyHellShell: A tool for file encryption and obfuscation.")

    parser.add_argument("-i", "--input", required=True, help="Path to the input file.")
    parser.add_argument("-e", "--encryption", choices=["xor", "rc4", "aes256"], help="Encryption method.")
    parser.add_argument("-k", "--key", help="Encryption key.")
    parser.add_argument("-o", "--obfuscation", choices=["ipv4", "ipv6", "mac", "uuid"], help="Obfuscation method.")
    parser.add_argument("-f", "--format", choices=["c", "raw"], default="c", help="Output format (C array or raw text file).")
    parser.add_argument("-out", "--output", help="Path to the output file.")

    if len(sys.argv) < 2: 
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Debug 
    print(f"\n[i] Input file          : {args.input}")
    print(f"[i] Encryption method   : {args.encryption}")
    print(f"[i] Obfuscation method  : {args.obfuscation}")
    print(f"[i] Output format       : {args.format}")
    print(f"[i] Output file         : {args.output}\n")

    return args 

def format_as_c_array(data: bytes) -> str:
    return ', '.join(f'0x{byte:02x}' for byte in data)

def main(): 
    args = argparser() 
    input_file = args.input
    output_file = args.output
    encryption_method = args.encryption
    obfuscation_method = args.obfuscation
    key = args.key
    
    if args.encryption and not args.obfuscation and args.format != 'raw':
        sys.exit("[-] When only encryption is used, output format (-f) must be 'raw'.")

    # Read input file 
    with open(input_file, "rb") as file: 
        file_data = file.read()

    payload_size = len(file_data)

    # Encryption 
    encrypted_data = None 
    if encryption_method != None:
        if key == None:
            print("[-] Please specify key with -k or --key.")
            sys.exit(1)

        match encryption_method:
            case "xor":
                encrypted_data = XOR(file_data, key)
            case "rc4": 
                encrypted_data = rc4(file_data, key.encode())
            case "aes256":
                encrypted_data = aes256_cbc_encrypt(file_data, key.encode())
                print(f"[+] IV (C array): {{{ format_as_c_array(aes_IV) }}}")
            case _:
                print("[-] Invalid encryption method")
                sys.exit(1)

    # Obfuscation 
    if encrypted_data != None:
        file_data = encrypted_data
    
    if obfuscation_method != None:
        match obfuscation_method: 
            case "ipv4":
                obfuscated_strings = ipv4fuscation(file_data)
            case "ipv6":
                obfuscated_strings = ipv6fuscation(file_data)
            case "mac":
                obfuscated_strings = macfuscation(file_data)
            case "uuid":
                obfuscated_strings = uuidfuscation(file_data)
            case _:
                print("[-] Invalid obfuscation method.")
                sys.exit(1)

    # Output
    if args.format == "c":
        if output_file != None: 
            print("[-] Output file not supported with C array output.")
            sys.exit(1)
            
        print(f"{outputCArray(obfuscated_strings, obfuscation_method)}")
        print(f"#define NumberOfElements {len(obfuscated_strings)}")
        print(f"#define PayloadSize {payload_size}")

    elif args.format == "raw":
        if output_file == None:
            print("[-] Please specify output file path with -out or --output.")
            sys.exit(1)

        # If encrypted + obfuscated, save the obfuscated string to file 
        if obfuscation_method != None: 
            result = saveRawToFile(obfuscated_strings, output_file, "obfuscated")
            print(f"[+] Saved to file: {output_file}")

        # If only encrypted, save the encrypted data to file 
        else:
            result = saveRawToFile(encrypted_data, output_file, "encrypted")
            if result:
                print(f"[+] Saved to file: {output_file}")
            else:
                print("[-] Could not save output to file.")
                sys.exit(1)

        print(f"\n#define PayloadSize {payload_size}")

    # Maybe add more output formats? idk. 
    else:
        print("[-] Invalid output format.")
        sys.exit(1)

if __name__ == "__main__":
    main()
