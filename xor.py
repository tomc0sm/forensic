
# Simple Xor Functions 
# xor_string make xor between two strings 
# xor_bin make xor between two files 
#
#   https://en.wikipedia.org/wiki/XOR_cipher
#   EXAMPLE XOR "Wiki" 8-bit encode ascii
#     01010111 01101001 01101011 01101001
#     11110011 11110011 11110011 11110011
#     10100100 10011010 10011000 10011010

from binascii import hexlify, unhexlify
from itertools import  cycle
import hashlib
import re
import string

#  bitwise XOR of bytestrings
def binXor(a,b):
    return bytes([ x^y for (x,y) in zip(a, cycle(b))])

#calcul file MD5 checksum
def getMD5(file_content_in_bytes):
    return hashlib.md5(file_content_in_bytes).hexdigest()

#https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility
# extract strings from file
def strings(filename, min=4):
    with open(filename, errors="ignore") as f:  # Python 3.x
    # with open(filename, "rb") as f:           # Python 2.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result
#  Simple Test
'''
a = bytearray("01010111011010010110101101101001","utf8")
b = bytearray("11110011111100111111001111110011", "utf8")
print(binXor(a,b).hex())
''' 
# Simple Find Key 
'''
a = bytes.fromhex("4d5a90")
b = bytes.fromhex("392F64")
print(binXor(a,b).hex())
'''
# Find Key 
'''
key = "66414E75713377446271743841323672"
fistLine = "392F646744626D743841322B7266414E"
for i in range (0,len(key)):
    a = bytes.fromhex(key)
    decrypt = binXor(bytes.fromhex(fistLine),a)
    print(decrypt.hex())
    key = key[1:] + key[0]
'''
# Xor binary file 
'''
basePath = "C:/Users/tom/Documents/PERSO/CNAM/Exos Forensic/SEC102 - 110 - Analyse de code malveillant/Obfsucation/"
encryptFileName = "49B1C8F19CEB9A776C2114557CF2D5C1"
keyFileName="49B1C8F19CEB9A776C2114557CF2D5C1.key"
with open (basePath + keyFileName, "rb") as f :
    key = f.read()
with open (basePath + encryptFileName, "rb") as f :
    encrypt = f.read()
    decrypt=binXor(encrypt,key)
    decryptFileName = getMD5(decrypt)
with open (basePath + decryptFileName, "wb") as f :
    f.write(decrypt)
print(decryptFileName)
for s in strings(basePath + decryptFileName, 8):
    print(s)
'''
'''
basePath = "C:/Users/tom/Documents/PERSO/CNAM/Exos Forensic/SEC102 - 110 - Analyse de code malveillant/Obfsucation/"
decryptFileName = "54E8914D704E4B564720BACF7C665F50"
for s in strings(basePath + decryptFileName, 8):
    print(s)
'''

# Key Rotation  1 : hex string treatment solution 

basePath = "C:/Users/tom/Documents/PERSO/CNAM/Exos Forensic/SEC102 - 110 - Analyse de code malveillant/Obfsucation/"
encryptFileName = "49B1C8F19CEB9A776C2114557CF2D5C1"
decryptFileName = "49B1C8F19CEB9A776C2114557CF2D5C1.key"
result = []
rotateKey = "337744627174384132367266414E7571"
dotIndex = 10 

for i in range (0,80) : # i is a CFF Editor line =  key size = 16 octets / 128 bits block
    if i == 0 :
        result.append("33770A44627174384132367266414E")
    elif (i % 24) % 5 == 0 : # key rotation frequency 5 lines = 80 octets = 640 bits block    
        rotateKey = rotateKey[2:] + rotateKey[0] + rotateKey [1]
        dotRotateKey = rotateKey[:-2]
        dotRotateKey = dotRotateKey[:dotIndex] + '0A' + dotRotateKey[dotIndex:]
        dotIndex = (dotIndex + 6) % len(rotateKey)
        result.append(dotRotateKey)
    else : 
        result.append(rotateKey)
key = ""
for i in range (len(result)-1, -1, -1):
    key += result[i]
with open (basePath + decryptFileName, "w") as f :
    n = 32 
    out = [key[i:i+n] for i in range(0, len(key), n)]
    for i in range(0 , len(out)):
        f.write(out[i]+'\n')
print("ok")
