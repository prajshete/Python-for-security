
#https://github.com/prajshete/Python-for-security.git
import pefile
import hashlib
import os
import re

def get_file_details(file_path):

    try:
        # Open the executable file
        pe = pefile.PE(file_path)

        # Display the file name
        file_name = os.path.basename(file_path)
        print("File Name:", file_name)

        # Get the size of the executable
        file_size = pe.OPTIONAL_HEADER.SizeOfImage
        print("File Size:", file_size)

        # Calculate the MD5 hash
        with open(file_path, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
        print("MD5 Hash:", md5_hash)

        # Calculate the SHA256 hash
        with open(file_path, 'rb') as f:
            data = f.read()
            sha256_hash = hashlib.sha256(data).hexdigest()
        print("SHA256 Hash:", sha256_hash)

    except pefile.PEFormatError as e:
        print("Error:", str(e))



# Extract the IP address and domain names from the executable

def extract_strings(filename):
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Regular expression pattern for IP addresses
    domain_pattern = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"  # Regular expression pattern for domain names/URLs

    with open(filename, "rb") as f:
        content = f.read().decode(errors="ignore")

        print("\nStrings:")
        print("--------")

        strings = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}", content)  # Extract all printable strings
        for s in strings:
            if re.search(ip_pattern, s) or re.search(domain_pattern, s):
                print(s)



def extract_imports(pe):
    print("\nImported Libraries and Functions:")
    print("--------------------------------")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("Library: {}".format(entry.dll.decode()))
        for imp in entry.imports:
            print("  Function: {}".format(imp.name.decode()))
        print()

    
# Provide the path to your executable file
file_path = "C:\Windows\System32\calc.exe"
pe = pefile.PE(file_path)

# Call the function to extract details
get_file_details(file_path)
extract_strings(file_path)
extract_imports(pe)