#!/usr/bin/env python3
import hashlib
import binascii




words = [line.strip().lower() for line in open('words.txt')]

# Compute the MD5 hash of this example password
password = 'moose' # type=string
passwords = [line.strip().lower() for line in open('passwords_hash.txt')]
userpassList = {}

#Create dictonary of key/value pairs
for line in passwords:
    info = line.split(':')
    username = info[0]
    pword = info[1]
    userpassList[username] = pword
#print(userpassList)

#create dictionary of {key, value} pairs that consist of 
# {hash, password}
# we'll have to encode/hash/hasashexstring for each word in words.txt
# we can then check each pword from userpassList against the keys in our new dictionary

hashDict = {}
for line in words:
    encodedPassword = line.encode('utf-8') # type=bytes
    md5 = hashlib.md5(encodedPassword)
    passwordHash = md5.digest() # type=bytes
    passwordHashAsHex = binascii.hexlify(passwordHash) # weirdly, still type=bytes
    passwordHashAsHexString = passwordHashAsHex.decode('utf-8') # type=string
    hashDict[passwordHashAsHexString] = line

crackedPasswords = {}
for key in userpassList:
    pword = userpassList[key]
    if pword in hashDict: 
        crackedPasswords[key] = hashDict[pword] 

passFile = open("passwords1.txt", "w")
for line in crackedPasswords:
    passFile.write(line + ":" + crackedPasswords[line] + "\n")

print(len(hashDict))

'''
for key in userpassList:
    passwordHash = userpassList[key]
    passwordHashAsHex = binascii.hexlify(passwordHash) # weirdly, still type=bytes
    passwordHashAsHexString = passwordHashAsHex.decode('utf-8') # type=string
    passwordString = passwordHashasHexString.decode('hex') # type=string
    print passwordString
'''

'''
print('password ({0}): {1}'.format(type(password), password))

encodedPassword = password.encode('utf-8') # type=bytes
print('encodedPassword ({0}): {1}'.format(type(encodedPassword), encodedPassword))

md5 = hashlib.md5(encodedPassword)
passwordHash = md5.digest() # type=bytes
print('passwordHash ({0}): {1}'.format(type(passwordHash), passwordHash))

passwordHashAsHex = binascii.hexlify(passwordHash) # weirdly, still type=bytes
print('passwordHashAsHex ({0}): {1}'.format(type(passwordHashAsHex), passwordHashAsHex))

passwordHashAsHexString = passwordHashAsHex.decode('utf-8') # type=string
print('passwordHashAsHexString ({0}): {1}'.format(type(passwordHashAsHexString), passwordHashAsHexString))
'''