
from pwn import *
import re

iterations = 1

def solveQuestion(question):
    num1 = int(question.split('(')[1].split(',')[0])
    num2 = int(question.split(', ')[2].split(')')[0])
    op = question.split("'")[1]
    
    print(f'{iterations} - Question: {num1}{op}{num2}')
    
    if op == '+':
        return str(num1+num2)
    elif op == '-':
        return str(num1-num2)
    elif op == '*':
        return str(num1*num2)
    elif op == '/':
        return str(round(num1/num2,1))

r = remote('192.168.34.154', 1337)

banner = r.recvuntil('>').decode('utf-8')
print(banner)

question = re.search(r"\(\d.*", banner).group(0)

while question is not None and iterations <= 1001:
    answer = solveQuestion(question)
    r.sendline(answer)
    response = r.recvline().decode('utf-8')
    try:
        question = re.search(r"\(\d.*", response).group(0)
    except:
        print(response)
        print(r.recvall(1024).decode('utf-8'), flush=True)
        break
    iterations += 1

print()
