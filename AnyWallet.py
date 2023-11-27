import hashlib
import base58
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import ecdsa
import requests
import json
import secrets

def generate_random_hex(length):
    return secrets.token_hex(length // 2)  # `length // 2` because each hex character represents 4 bits

def password_to_private_key(password):
    # Use a hash function (e.g., SHA-256) to derive a key from the password
    if usePassword == 'y': key = hashlib.sha256(password.encode('utf-8')).digest()

    # Use the derived key as a seed for the ECDSA signing key
    if usePassword == 'y': private_key = SigningKey.from_string(key, curve=SECP256k1)

    # If not using a password then randomly generate address
    if usePassword == 'n': private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    
    return private_key

def private_key_to_public_key(private_key):
    # Get the corresponding public key
    public_key = private_key.verifying_key
    public_key_bytes = public_key.to_string('compressed')
    
    return public_key_bytes

def public_key_to_address(public_key):
    # Hash the public key using SHA-256 and then RIPEMD-160
    hashed_public_key = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()

    # Add the version byte for mainnet (0x00) or testnet (0x6f)
    #####version_byte = b'\x00'  # for mainnet
    #####hashed_public_key_with_version = version_byte + hashed_public_key
    hashed_public_key_with_version = theVersionByte + hashed_public_key
    
    # Perform double SHA-256 hash to get the checksum
    checksum = hashlib.sha256(hashlib.sha256(hashed_public_key_with_version).digest()).digest()[:4]

    # Concatenate the hashed public key with the checksum
    address_data = hashed_public_key_with_version + checksum

    # Convert the address to base58
    bitcoin_address = base58.b58encode(address_data).decode('utf-8')

    return bitcoin_address

def private_key_to_wifc(private_key):
    # Get the private key as bytes
    private_key_bytes = private_key.to_string()

    # Add the version byte (0x80 for mainnet)
    #####version_byte = b'\x80'
    
    # Add the compression flag (0x01) for compressed public key
    compression_flag = b'\x01'

    # Concatenate the version byte, private key, and compression flag
    #####wifc_data = version_byte + private_key_bytes + compression_flag
    wifc_data = theWifcVersionByte + private_key_bytes + compression_flag

    # Perform double SHA-256 hash to get the checksum
    checksum = hashlib.sha256(hashlib.sha256(wifc_data).digest()).digest()[:4]

    # Concatenate the WIFC data with the checksum
    wifc_key = base58.b58encode(wifc_data + checksum).decode('utf-8')

    return wifc_key

# Example usage

usePassword = input('Generate address from password? (y/n): ')
if usePassword != 'y' and usePassword != 'n': usePassword = 'n'

print("")
print("These next set of questions are the Network Version and Private Key bytes.")
print("For most coins, these are stored in the coin's github repository, in chainparams.cpp")
print("")
print("The tricky thing, they are stored in Decimal Format in the chainparams.cpp file")
print("This program uses the Hexadecimal format to run it's calculations")
print("For Example, Bitcoin uses the following code to choose these:")
print("base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0); --- the 0 is network version byte in Decimal")
print("base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128); --- the 128 is the Private Key byte in Decimal")
print("If you're a wizard, you can convert this in your head, or you can use a Decimal to Hexadecimal converter to Calculate")
print("The Bitcoin Network Version Byte in Decimal = 0, in Hexadecimal = 00")
print("The Bitcoin Private Key Byte in Decimal = 128, in Hexadecimal = 80")
print("")

nvb = str(input("Enter The Network Version Byte in hexadecimal format (example Bitcoin = 00): "))
##print(nvb)

tempVersionByte = '\x00'
print("+ start" + tempVersionByte + "end")
print(", start", tempVersionByte, "end")
theVersionByte = bytes(tempVersionByte, encoding= 'utf-8')
print(theVersionByte)

print ("")

tempint1 = 0
tempint2 = 0

if ord(nvb[0]) < 58:
    tempint1 = ord(nvb[0]) - 48
elif ord(nvb[0]) > 96:
    tempint1 = ord(nvb[0]) - 87

if ord(nvb[1]) < 58:
    tempint2 = ord(nvb[1]) - 48
elif ord(nvb[1]) > 96:
    tempint2 = ord(nvb[1]) - 87

nextempVersionByte = chr((16 * tempint1) + tempint2)
    

#tvb = "\\x" + nvb
#nextempVersionByte = tvb[-4:]
#print (nextempVersionByte)

#####nextempVersionByte = str('\\') + "x" + str(nvb)
##nextempVersionByte = nvb
print ("+ start" + nextempVersionByte + "end")
print (", start", nextempVersionByte, "end")
theVersionByte = bytes(nextempVersionByte, encoding= 'utf-8')
#theVersionByte = nvb
print (theVersionByte)

#####test = "\\"
#####print(test)
#####test = '\X'
#####tempVersionByte = test + nvb
#####print (bytes(nvb, encoding= 'utf-8'))
#theVersionByte = b'\\x'+nvb
#print (tempVersionByte)
#tempVersionByte = tempVersionByte[-4]
#print (tempVersionByte)
#tempVersionByte = '\x00'
#print("yo ", tempVersionByte)
###################theVersionByte = bytes(tempVersionByte, encoding= 'utf-8')
print(theVersionByte)

###pkb = input("Enter The Private Key Byte in hexadecimal format (example Bitcoin = 80): ")
###tempWifcVersionByte = '\\x'+ pkb
fuckWifcVersionByte = '\x80'
print(fuckWifcVersionByte)
theWifcVersionByte = bytes(fuckWifcVersionByte, encoding= 'utf-8')
print(theWifcVersionByte)

balance = 0
while balance == 0:
    if usePassword == 'y': password = input('enter password:')
    if usePassword == 'n': password = ""
    private_key = password_to_private_key(password)
    public_key = private_key_to_public_key(private_key)
    bitcoin_address = public_key_to_address(public_key)
    wifc_key = private_key_to_wifc(private_key)

    print("Bitcoin Address:", bitcoin_address)
    print("Private Key (hex):", private_key.to_string().hex())
    print("WIFC Key:", wifc_key)

    f = open("Insert You File Path Here!!!!", "a")
    f.write(bitcoin_address + ',' + wifc_key + '\n')
    f.close()

    tickers = requests.get('https://chain.api.btc.com/v3/address/' + bitcoin_address)
    tickers_obj = json.loads(tickers.content)
    print("recieved: ", tickers.json()['data']['received'])
    print("balance: ", tickers.json()['data']['balance'])
    balance = tickers.json()['data']['balance']
