import requests

shells = open('shells.txt').readlines()

for shell in shells:
    if requests.get('http://10.10.10.181/' + shell.strip('\n')).ok == True:
        print(shell.strip('\n'), 'is present')

