import sys
import re
import uuid

def bytes_to_uuid(byte_chunk):
    """Converts a 16-byte chunk into a UUID."""
    return str(uuid.UUID(bytes=byte_chunk))

def uuid_obfuscate_buf_from_file(file_path: str):
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

    # Padding to make sure the byte array is divisible by 16
    padding_needed = (16 - (len(data) % 16)) % 16
    data += bytearray([0x00] * padding_needed)

    # Convert bytes to UUIDs
    uuids = [bytes_to_uuid(data[i:i + 16]) for i in range(0, len(data), 16)]

    # Generate the C# code for the UUIDs
    csharp_uuids = '\n'.join(f'Guid.Parse("{uuid_str}")' for uuid_str in uuids)
    csharp_output = f"Guid[] uuids = new Guid[] {{\n{csharp_uuids}\n}};\n"

    # Generate the decryption code to convert UUIDs back to bytes and remove padding
    decryption_code = (
        "\nbyte[] buf = new byte[uuids.Length * 16];\n"
        "int index = 0;\n"
        "foreach (Guid guid in uuids)\n"
        "{{\n"
        "    byte[] guidBytes = guid.ToByteArray();\n"
        "    Array.Copy(guidBytes, 0, buf, index, guidBytes.Length);\n"
        "    index += 16;\n"
        "}}\n"
        "// Remove padding (0x00 bytes)\n"
        "List<byte> originalData = new List<byte>();\n"
        "for (int j = 0; j < buf.Length; j++)\n"
        "{{\n"
        "    if (buf[j] != 0x00) {{ originalData.Add(buf[j]); }}\n"
        "}}\n"
        "buf = originalData.ToArray();\n"
    )

    # Combine both parts
    csharp_output += decryption_code

    # Print the C# compatible UUID array and decryption code
    print(csharp_output)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 uuid_obfuscation.py <file.txt>")
        sys.exit(1)

    file_path = sys.argv[1]

    uuid_obfuscate_buf_from_file(file_path)
