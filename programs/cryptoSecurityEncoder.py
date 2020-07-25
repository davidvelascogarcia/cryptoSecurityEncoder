'''
 * ************************************************************
 *      Program: Crypto Security Encoder
 *      Type: Python
 *      Author: David Velasco Garcia @davidvelascogarcia
 * ************************************************************
'''
# Libraries
import base64
import binascii
import configparser
import datetime
import os
import platform
import sys
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

print("**************************************************************************")
print("**************************************************************************")
print("                   Program: Crypto Security Encoder                       ")
print("                     Author: David Velasco Garcia                         ")
print("                             @davidvelascogarcia                          ")
print("**************************************************************************")
print("**************************************************************************")

print("")
print("Starting system ...")
print("")

print("")
print("Loading Crypto Security Encoder engine ...")
print("")

print("")
print("Initializing cryptoSecurityEncoder engine ...")
print("")

# Get system configuration
print("")
print("Detecting system and release version ...")
print("")
systemPlatform = platform.system()
systemRelease = platform.release()

print("")
print("**************************************************************************")
print("Configuration detected:")
print("**************************************************************************")
print("")
print("Platform:")
print(systemPlatform)
print("Release:")
print(systemRelease)

print("")
print("**************************************************************************")
print("Authentication:")
print("**************************************************************************")
print("")

loopControlFileExists = 0

while int(loopControlFileExists) == 0:
    try:
        # Get autentication data
        print("")
        print("Getting authentication data ...")
        print("")
        authenticationObject = configparser.ConfigParser()
        authenticationObject.read('../config/authentication.ini')
        authenticationObject.sections()

        userID = authenticationObject['Authentication']['user-id']
        derivedKeyPassword = authenticationObject['Authentication']['derivedKey-password']
        derivedKeySalt =  authenticationObject['Authentication']['derivedKey-salt']
        derivedKeyLength = authenticationObject['Authentication']['derivedKey-length']
        derivedKeyIterations = authenticationObject['Authentication']['derivedKey-iterations']
        derivedKeyHashModule = authenticationObject['Authentication']['derivedKey-hashmodule']
        cryptoNonce = authenticationObject['Authentication']['crypto-nonce']

        print("User ID: " + str(userID))
        print("Derived key password: " + str(derivedKeyPassword))
        print("Derived key salt: " + str(derivedKeySalt))
        print("Derived key length: " + str(derivedKeyLength))
        print("Iterations: " + str(derivedKeyIterations))
        print("HMAC Hash module: " + str(derivedKeyHashModule))
        print("Crypto nonce: " + str(cryptoNonce))
        print("")

        cryptoNonce = base64.b64encode(bytes(cryptoNonce, 'utf-8'))

        # Select hmac_hash_module, by default SHA512
        if str(derivedKeyHashModule) == "SHA256":
            derivedKeyHashModule = SHA256

        elif str(derivedKeyHashModule) == "SHA512":
            derivedKeyHashModule = SHA512

        else:
            derivedKeyHashModule = SHA512

        loopControlFileExists = 1

    except:
        print("")
        print("[ERROR] Sorry, athentication.ini not founded, waiting 4 seconds to the next check ...")
        print("")
        time.sleep(4)

print("")
print("[INFO] Data obtained correctly.")
print("")

# Generate derived key
print("")
print("**************************************************************************")
print("Derived key generator:")
print("**************************************************************************")
print("")
print("[INFO] Initializing derived key generator ...")
print("")
print("Configure parameters:")
print("")
print("Derived key password: " + str(derivedKeyPassword))
print("Derived key salt: " + str(derivedKeySalt))
print("Derived key length: " + str(derivedKeyLength))
print("Iterations: " + str(derivedKeyIterations))
print("HMAC Hash module: " + str(derivedKeyHashModule))
print("")

# Generating derived key
print("")
print("Generating derived key ... ")
print("")

derivedKey = PBKDF2(password=derivedKeyPassword, salt=derivedKeySalt, dkLen=int(derivedKeyLength), count=int(derivedKeyIterations), hmac_hash_module=derivedKeyHashModule)

print("")
print("[INFO] Key generated correctly at " + str(datetime.datetime.now()) + ".")
print("")

print("")
print("**************************************************************************")
print("Derived key:")
print("**************************************************************************")
print("")

binaryDerivedKey = derivedKey

print("")
print("Binary derived key: ", binaryDerivedKey)
print("")

base64DerivedKey = binascii.b2a_base64(binaryDerivedKey)

print("")
print("Base64 derived key: ", base64DerivedKey)
print("")

stringDerivedKey =str(base64DerivedKey)
stringDerivedKey =stringDerivedKey[2:-3]

print("")
print("String derived key:", stringDerivedKey)
print("")

print("")
print("**************************************************************************")
print("Encrypting message:")
print("**************************************************************************")
print("")
print("Configure parameters:")
print("")
print("Binary Derived key: " + str(binaryDerivedKey))
print("AES mode: GCM")
print("Nonce: " + str(cryptoNonce))
print("")

print("")
print("[INFO] Initializing  encryption process ...")
print("")

print("")
print("[INFO] Please, enter message to encrypt:")
print("")

dataToEncode = input()

print("")
print("[INFO] Message to encrypt: " + str(dataToEncode))
print("")

dataToEncrypt = base64.b64encode(bytes(dataToEncode, 'utf-8'))

print("")
print("[INFO] Encrypting message ...")
print("")

# Creating encryptor engine
cryptoEngine = AES.new(binaryDerivedKey, AES.MODE_GCM, nonce=cryptoNonce)

# Encrypting message
cryptoMessage, cryptoTag = cryptoEngine.encrypt_and_digest(dataToEncrypt)

print("")
print("[INFO] Encryption done correctly at " + str(datetime.datetime.now()) + ".")
print("")


print("")
print("**************************************************************************")
print("Encrypted message:")
print("**************************************************************************")
print("")
print("Binary encrypted message: " + str(cryptoMessage))
print("Binary encrypted tag: " + str(cryptoTag))
print("")

base64EncryptedMessage = binascii.b2a_base64(cryptoMessage)
base64EncryptedTag = binascii.b2a_base64(cryptoTag)

print("")
print("Base64 encrypted message: "+ str(base64EncryptedMessage))
print("Base64 encrypted tag: "+ str(base64EncryptedTag))
print("")

print("")
print("**************************************************************************")
print("Decrypting message:")
print("**************************************************************************")
print("")
print("[INFO] Decrypting message ...")
print("")

# Decrypting message
deCryptoEngine = AES.new(binaryDerivedKey, AES.MODE_GCM, nonce=cryptoNonce)
deCryptoMessage = deCryptoEngine.decrypt(cryptoMessage)

print("")
print("[INFO] Decryption message process done correctly.")
print("")

try:
    print("")
    print("**************************************************************************")
    print("Verifying message:")
    print("**************************************************************************")
    print("")
    print("[INFO] Verifying cryptoTag ....")
    print("")

    deCryptoEngine.verify(cryptoTag)

    print("")
    print("[INFO] cryptoTag verified correctly.")
    print("")

    print("")
    print("**************************************************************************")
    print("Decoding message:")
    print("**************************************************************************")
    print("")
    print("Decoding decrypted message ...")
    print("")

    deCryptedMessage = base64.b64decode(deCryptoMessage).decode('utf-8')

    print("")
    print("[INFO] Decoding message process done correctly.")
    print("")
    print("[INFO] Decrypted message: " + str(deCryptedMessage))
    print("")

except ValueError:
    print("")
    print("[ERROR] Error decrypting message, maybe the key or tag have errors or are incorrect.")
    print("")

print("")
print("")
print("**************************************************************************")
print("Program finished:")
print("**************************************************************************")
print("")
print("cryptoSecurityEncoder program finished correctly.")
print("")

userExit = input()
