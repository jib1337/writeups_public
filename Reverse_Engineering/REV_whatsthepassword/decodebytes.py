with open('obfsflag.txt', 'r') as file:
    hexout = file.readlines()

enc = [line.split()[1][:2] for line in hexout]

print('rtcp{fL92_r_', end='')
for byte in enc:
    if byte == '00': continue
    print(chr(((int(byte, 16) ^ 0x32) - 1) ^ 0x32), end='')
print('}')
