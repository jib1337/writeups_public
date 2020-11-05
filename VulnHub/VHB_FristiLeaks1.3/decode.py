import sys, codecs, base64

def decodeString(encoded):
    base64String = codecs.decode(encoded, 'rot-13')[::-1]
    return base64.b64decode(base64String)

print decodeString(sys.argv[1])
