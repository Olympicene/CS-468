import csv

import hashlib

import string

import time

start_time = time.time()


# passwords folder

shadow = "shadow"

# dictionary

dictionary_file = "dictionary.txt"




def user6():

    with open(dictionary_file, 'r') as csvfile:

        dictionary = csv.reader(csvfile)


        for entry in dictionary:

            password = entry[0]


            # bash sha 224

            hash = hashlib.sha3_224(password.encode('utf-8')).hexdigest()

            if hash == "b9703614d138ef18234e74df390c58b39a63b10ac56134d56e61d097":

                print(f"found it: {password}")

user6()
