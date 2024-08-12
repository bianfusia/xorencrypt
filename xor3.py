import sys
import re

def xor_encrypt_buf_to_csharp(key: bytes, buf_string: str):
    # Extract byte array from the provided C# code string
    match = re.search(r'byte\[\] buf = new byte\[\d+\] \{(.*?)\};', buf_string)
    if not match:
        print("Invalid input format. Expected: byte[] buf = new byte[752] {0xfe, 0x4a, ... };")
        sys.exit(1)
    
    # Convert the extracted byte string into a bytearray
    byte_string = match.group(1)
    data = bytearray(int(byte, 16) for byte in byte_string.split(', '))

    # XOR the data with the key
    encrypted_data = bytearray()
    key_length = len(key)
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % key_length])

    # Format the output for C#
    byte_array_string = ', '.join(f'0x{byte:02x}' for byte in encrypted_data)
    csharp_output = f"byte[] buf = new byte[{len(encrypted_data)}] {{{byte_array_string}}};\n"

    # Generate the decryption loop with hardcoded key
    decryption_code = (
        "\nbyte[] key = new byte[] {{{key_string}}};\n"
        "for(int i = 0; i < buf.Length; i++)\n"
        "{{\n"
        "    buf[i] = (byte)(buf[i] ^ key[i % key.Length]);\n"
        "}}\n"
    ).format(key_string=', '.join(f'0x{byte:02x}' for byte in key))

    # Combine both parts
    csharp_output += decryption_code

    # Print the C# compatible byte array and decryption code
    print(csharp_output)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 xor_from_buf.py <key> <\"byte[] buf = ...\">")
        sys.exit(1)

    key = sys.argv[1].encode()  # Convert the key to bytes
    buf_string = sys.argv[2]

    xor_encrypt_buf_to_csharp(key, buf_string)
