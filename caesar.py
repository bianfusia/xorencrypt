import sys
import re

def caesar_encrypt_buf_from_file(rot: int, file_path: str):
    # Read the content of the file
    with open(file_path, 'r') as file:
        buf_string = file.read()

    # Extract the byte array from the provided C# code string
    match = re.search(r'byte\s*\[\s*\]\s*buf\s*=\s*new\s*byte\s*\[\s*\d+\s*\]\s*\{(.*?)\};', buf_string, re.DOTALL)
    if not match:
        print("Invalid input format. Expected: byte[] buf = new byte[752] {0xfe, 0x4a, ... };")
        sys.exit(1)
    
    # Clean and split the byte string
    byte_string = match.group(1).replace('\n', '').replace('\r', '').replace(' ', '')
    data = bytearray(int(byte, 16) for byte in byte_string.split(','))

    # Apply the Caesar cipher (shift by ROT value)
    encrypted_data = bytearray((byte + rot) % 256 for byte in data)

    # Format the output for C#
    byte_array_string = ', '.join(f'0x{byte:02x}' for byte in encrypted_data)
    csharp_output = f"byte[] buf = new byte[{len(encrypted_data)}] {{{byte_array_string}}};\n"

    # Generate the decryption loop with hardcoded ROT and variable `j`
    decryption_code = (
        "\nint rot = {rot};\n"
        "for(int j = 0; j < buf.Length; j++)\n"
        "{{\n"
        "    buf[j] = (byte)(((int)buf[j] - rot + 256) % 256);\n"
        "}}\n"
    ).format(rot=rot)

    # Combine both parts
    csharp_output += decryption_code

    # Print the C# compatible byte array and decryption code
    print(csharp_output)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 caesar.py <ROT> <file.txt>")
        sys.exit(1)

    rot = int(sys.argv[1])  # Convert the ROT value to an integer
    file_path = sys.argv[2]

    caesar_encrypt_buf_from_file(rot, file_path)
