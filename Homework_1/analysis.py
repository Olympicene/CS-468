import csv
import hashlib
import string
import time
from collections import Counter
from varname import nameof
import re
encrypted_file = "plaintext.txt"


# get initial count of letters
def countLetters():
    file = open(encrypted_file, "r")
    encrypted_text = file.read()

    print(Counter(encrypted_text).most_common())

# convert tuples to dictionary https://www.geeksforgeeks.org/python-convert-a-list-of-tuples-into-dictionary/
def Convert(tuples, dictionary):
    for a, b in tuples:
        dictionary.setdefault(a, b)
    return dictionary

def Reverse(tuples, dictionary):
    for a, b in tuples:
        dictionary.setdefault(b, a)
    return dictionary

# replace all letters simultaneously https://stackoverflow.com/a/15448887
def multiple_replace(string, rep_dict):
    pattern = re.compile("|".join([re.escape(k) for k in sorted(rep_dict,key=len,reverse=True)]), flags=re.DOTALL)
    return pattern.sub(lambda x: rep_dict[x.group(0)], string)

# use substitution map
def userSubstitution(subMap=None):
    file = open(encrypted_file, "r")
    encryptedText = file.read()
    print("--------------------------------------------------------")
    print(f"using map {nameof(subMap)}: {subMap}")
    print("--------------------------------------------------------")
    
    if subMap == None:
        print(encryptedText)
    else:
        subDictionary = Convert(subMap, {})
        substituteText = multiple_replace(encryptedText, subDictionary)
        print(substituteText)


def commonLetterMap():
    # get a map of most common letters here to most common in english overall
    letters = [('h', 80), ('m', 53), ('j', 50), ('b', 50), ('s', 45), ('e', 45), ('y', 41), ('v', 32), ('d', 31), ('c', 30), ('f', 22), ('a', 20), ('g', 19), ('z', 19), ('l', 17), ('r', 17), ('q', 17), ('w', 14), ('u', 12), ('o', 11), ('x', 6), ('n', 2), ('t', 2), ('k', 1)]
    mostCommonLetters = ['e', 'a', 'r', 'i', 'o', 't', 'n', 's', 'l', 'c', 'u', 'd', 'p', 'm', 'h', 'g', 'b', 'f', 'y', 'w', 'k', 'v', 'x', 'z', 'j', 'q']
    newLetters = []

    for index, (letter, num) in enumerate(letters):
        newLetters.append((letter, mostCommonLetters[index]))
    return newLetters

def main():
    # print original
    countLetters()
    userSubstitution()

    # common letter mapping not good enoughsubstitutePass
    # userSubstituion(commonLetterMap())

    # lot of single letters are 'm' so must be 'i'
    customV1 = [('m', 'i'), ('j', 'r'), ('b', 'a'), ('s', 'o'), ('e', 't'), ('y', 'n'), ('v', 's'), ('d', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('q', 'b'), ('w', 'f'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV1)

    # 'e' shows up in a lot of 2 letters words as the first or last letter, as well as being together in the middle of a word, must be 'o'
    customV2 = [('m', 'i'), ('e', 'o'), ('h', 'e'), ('j', 'r'), ('b', 'a'), ('s', 't'), ('y', 'n'), ('v', 's'), ('d', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('q', 'b'), ('w', 'f'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV2)

    # 'eqq' must be 'off' because thats the only word i can think of that goes there so 'q' = 'f'
    customV3 = [('m', 'i'), ('e', 'o'), ('q', 'f'), ('h', 'e'), ('j', 'r'), ('b', 'a'), ('s', 't'), ('y', 'n'), ('v', 's'), ('d', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('w', 'b'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV3)

    # 's' = 'a' if 'm' is 'i'
    customV4 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('q', 'f'), ('h', 'e'), ('j', 'r'), ('b', 't'), ('y', 'n'), ('v', 's'), ('d', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('w', 'b'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV4)

    # 'd' = 's' because 'sd' should be 'as'
    customV5 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('q', 'f'), ('h', 'e'), ('j', 'r'), ('b', 't'), ('y', 'n'), ('v', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('w', 'b'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV5)

    # 'j' = 'n' because 'deej' should be 'soon'
    customV6 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('q', 'f'), ('h', 'e'), ('b', 't'), ('y', 'r'), ('v', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('w', 'b'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV6)

    # 'w' = 'c'
    customV7 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('w', 'c'), ('q', 'f'), ('h', 'e'), ('b', 't'), ('y', 'r'), ('v', 'l'), ('c', 'c'), ('f', 'u'), ('a', 'd'), ('g', 'p'), ('z', 'm'), ('l', 'h'), ('r', 'g'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV7)

    # 'f' = 'm'
    customV8 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('w', 'c'), ('f', 'm'), ('q', 'f'), ('h', 'e'), ('b', 't'), ('y', 'r'), ('v', 'l'), ('c', 'c'), ('a', 'd'), ('g', 'p'), ('z', 'u'), ('l', 'h'), ('r', 'g'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV8)

    # 'c' = 'h'
    customV9 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('w', 'c'), ('f', 'm'), ('c', 'h'), ('q', 'f'), ('h', 'e'), ('b', 't'), ('y', 'r'), ('v', 'l'), ('a', 'd'), ('g', 'p'), ('z', 'u'), ('l', 'h'), ('r', 'g'), ('u', 'y'), ('o', 'w'), ('x', 'k'), ('n', 'v'), ('t', 'x'), ('k', 'z')]
    # userSubstitution(customV9)

    customV10 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('w', 'c'), ('f', 'm'), ('c', 'h'), ('a', 'g'), ('u', 'v'), ('h', 'e'), ('v', 'l'), ('l', 'y'), ('y', 'r'), ('g', 'p'), ('r', 'd'),('o', 'w'), ('b', 't'), ('z', 'u'), ('x', 'b'), ('q', 'f'), ('k', 'q'), ('n', 'z'), ('t', 'k'), ('i', 'x'), ('p', 'j')]
    userSubstitution(customV10)

# main()

dictionary_file = "dictionary.txt"

def user7():
    with open(dictionary_file, 'r') as csvfile:
        dictionary = csv.reader(csvfile)

        customV10 = [('m', 'i'), ('e', 'o'), ('s', 'a'), ('d', 's'), ('j', 'n'), ('w', 'c'), ('f', 'm'), ('c', 'h'), ('a', 'g'), ('u', 'v'), ('h', 'e'), ('v', 'l'), ('l', 'y'), ('y', 'r'), ('g', 'p'), ('r', 'd'),('o', 'w'), ('b', 't'), ('z', 'u'), ('x', 'b'), ('q', 'f'), ('k', 'q'), ('n', 'z'), ('t', 'k')]
        encryptDictionary = Reverse(customV10, {})
        decryptDictionary = Convert(customV10, {})

        # customV10.sort(key=lambda a: a[1])
        # print(customV10)

        # print(decryptDictionary)

        for entry in dictionary:
            password = entry[0]
            

            subPassword = multiple_replace(password, encryptDictionary)
            # print(subPassword)

            hash = hashlib.sha3_224(subPassword.encode('utf-8')).hexdigest()
            if hash == "629e2ff9ca7ed98b03d2d70f4584c941e9da93c07b03047cdb9c8c3b":
                print(f"found it: {subPassword}")
user7()
    