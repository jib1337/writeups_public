# ------------ original function-------------
def comprehensive(k, m):

	#print(len(k), len(m))
	#k = 'munchkin'

	f = []
	for b in range(0, 24, 8):
		f1 = []
		for a in range(8):
			f1.append(ord(k[a]) ^ ord(m[a+b]))
		f.append(f1)

	g = []
	for b in f:
		for a in b:
			g.append(a)

	h = []
	for b in range(8):
		h1 = []
		for a in range(b, 24, 8):
			h1.append(g[a])
		h.append(h1)

	i = []
	for group in h:
		i1 = []
		for value in range(3):
			i1.append(group[value] ^ ord(k[value]))
		i.append(i1)

	fin = []
	for group in i:
		for value in group:
			fin.append(value + ord(k[0]))

	return(fin)

	#-------------------------------------------


m = 'tjctf{?????????????????}'.lower() #len 24
msum = 2613 # the total byte value sum of m
#k = '????????'.lower() # len 8
k = ''.join([chr(109), chr(63), chr(63), chr(63), chr(63), chr(63), chr(63), chr(63)]).lower()

targets = [225, 228, 219, 223, 220, 231, 205, 217, 224, 231, 228, 210, 208, 227, 220, 234, 236, 222, 232, 235, 227, 217, 223, 234]

# step 2 reverse print
reverse_fin = []
for val in targets:
	reverse_fin.append(val - ord(k[0]))
# print(reverse_fin)

# step 3 - start by grouping the list into groups of 3 values
reverse_fin_grouped = []
group = []
b = 0
for i in range(24):
	group.append(reverse_fin[i])
	b += 1
	if b == 3:
		reverse_fin_grouped.append(group)
		group = []
		b = 0

# step 3 - xor every first value the groups of 3 with the first known key value
# will make the first value of every group correct
i_rev_1 = reverse_fin_grouped
for group in range(8):
	for i in range(3):
		if i == 0:
			i_rev_1[group][0] = reverse_fin_grouped[group][0] ^ ord(k[0])
#print(i_rev_1)

# step 4 - reverse g
# just gonna make a new flattened list here.
g_rev = [25, 31, 13, 23, 14, 16, 22, 1, 19, 111, 108, 119, 118, 127, 126, 114, 110, 122, 115, 101, 111, 113, 118, 125]
#print(g)
#print(len(g))

# step 5 - loop for our first 8 message vals and xor with our known key val
knownkey = ''
knownmsg = 'tjctf{'
index = 0
for val in g_rev[:6]:
	for test in range(0,255):
		attempt = chr(val ^ test)
		if attempt == knownmsg[index]:
			knownkey += chr(test)
			index += 1
			break

knownkey += '??'
print(knownkey)

# step 6 - re-reverse i with new known key values
# first make them groups of 3
reverse_fin_grouped = []
group = []
b = 0
for i in range(24):
	group.append(reverse_fin[i])
	b += 1
	if b == 3:
		reverse_fin_grouped.append(group)
		group = []
		b = 0

# then xor each group with the first 3 vals of the key
i_rev_2 = reverse_fin_grouped
#print(i_rev_2)
for group in range(8):
	for i in range(3):
			i_rev_2[group][i] = reverse_fin_grouped[group][i] ^ ord(knownkey[i])
#print(i_rev_2)

#step 7/8 - permutate and re-reverse g
g_rev_2 = [25, 31, 13, 23, 14, 16, 22, 1, 2, 26, 25, 2, 3, 10, 11, 7, 0, 20, 29, 11, 1, 31, 24, 19]
#print(g_rev_2, len(g_rev_2))

# attempt another reverse of f with new known values
f_rev = ''
for interval in range(0, 24, 8):
	for keypos in range(8):
		f_rev += chr(ord(knownkey[keypos]) ^ g_rev_2[keypos+interval])

knownmessage = f_rev.split()

# step 9 - recover the } at the end and get another bit of the key
for test in range(0,255):
	attempt = chr(g_rev_2[-1] ^ test)
	if attempt == '}':
		knownkey = knownkey[:6] + '?' + chr(test)
		break
print(knownkey)

# step 10 - use known key to decrypt more
knownmessage = ''
for interval in range(0, 24, 8):
	for keypos in range(8):
		knownmessage += chr(ord(knownkey[keypos]) ^ g_rev_2[keypos+interval])

print(knownmessage)

# step 11 - stop playing nice and just brute force the final values
letters = 'abcdefghijklmnopqrstuvwxyz'
success_1 = []
success_keys = []
for letter in letters:
	key = 'munchk' + letter + 'n'
	for i in range(0,255):
		message = 'tjctf{' + chr(i) + 'ooowakabimashitq}'
		test = comprehensive(key, message)
		if test[18] == 232:
			success_1.append(i)
			success_keys.append(letter)

success_2 = []
success_keys2 = []
for letter in success_keys:
	key = 'munchk' + letter + 'n'
	for trial1 in success_1:
		for i in range(0,255):
			message = 'tjctf{' + chr(trial1) + 'ooowaka' + chr(i) + 'imashitq}'
			test = comprehensive(key, message)
			if test[18] == 232 and test[19] == 235:
				success_2.append(i)
				success_keys2.append(letter)

for letter in success_keys2:
	key = 'munchk' + letter + 'n'
	for trial1 in success_1:
		for trial2 in success_2:
			for i in range(0,255):
				message = 'tjctf{' + chr(trial1) + 'ooowaka' + chr(trial2) + 'imashit' + chr(i) + '}'
				test = comprehensive(key, message)
				if test[18] == 232 and test[19] == 235 and test[20] == 227 and sum([ord(s) for s in message]) == 2613:
					print(message, key)
