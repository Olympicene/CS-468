import csv
import hashlib
import string
import time
start_time = time.time()

# passwords folder
shadow = "shadow"
# dictionary
dictionary_file = "dictionary.txt"


def user1():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]

            # bash sha256
            hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if hash == "b00ef262afae566b51f740124a6b12d982a2cff1bbf2ab5632cb548e98da6feb":
                print(f"found it: {password}")
user1()

def user2():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]

            # bash sha 384
            hash = hashlib.sha384(password.encode('utf-8')).hexdigest()
            if hash == "886cf1efd877867fdcaff06bf2f93fdc7e9405807544fc3004782869b70cae94027807e3898c702d9eef4587b7a3500a":
                print(f"found it: {password}")
user2()

# converts to caesar cipher https://stackoverflow.com/a/8895517
alphabet = string.ascii_lowercase
def caesar(plaintext, shift):
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    table = str.maketrans(alphabet, shifted_alphabet)
    return plaintext.translate(table)

def user3():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]
            original = password
            
            # caesar cipher x26 times
            for i in range(26):
                password = caesar(password, 1)

                # bash sha512
                hash = hashlib.sha512(password.encode('utf-8')).hexdigest()
                if hash == "d7aa17fd07a2d1a30f491c1f2ff1cbbf256493e9c93707c9d326b82c16c23d2923ed32f518301b47b1feb371d87c1eb5bcb09f35520fa0d6f04b3e52285abab1":
                    print(f"found it: {password}")
user3()

# converts to l337 https://stackoverflow.com/a/10493539
def l337(plaintext):
    replacements = (('a','4'), ('e','3'), ('s','5'), ('i','1'), ('o','0'), ('t','7'))
    l337text = plaintext
    for old, new in replacements:
        l337text = l337text.replace(old, new)
    return l337text

def user4():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]

            # l337 conversion
            l33t_password = l337(password)

            # bash sha 1
            hash = hashlib.sha1(l33t_password.encode('utf-8')).hexdigest()
            if hash == "21d5c27a7e06317d1d02e0135a76454971e2c6d2":
                print(f"found it: {l33t_password}")
user4()

def user5():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]
            
            # add salt of every 5 digit number (except starting with 0)
            for i in range(10000, 100000):
                salted_password = password + str(i)

                # bash md5
                hash = hashlib.md5(salted_password.encode('utf-8')).hexdigest()
                if hash == "97d12b7bed2d352081b20a755d7fd410":
                    print(f"found it: {salted_password}")
# user5()

def user6():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        for entry in dictionary:
            password = entry[0]

            # bash sha 224
            hash = hashlib.sha224(password.encode('utf-8')).hexdigest()
            if hash == "45ac50939c87f368f39301f36e1dd069a7ed749e8bade13f46e29c70":
                print(f"found it: {password}")
user6()

print("--- %s seconds ---" % (time.time() - start_time))