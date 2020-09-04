# comprehensive | TJCTF2018

## Problem

Please teach me how to be a comprehension master, all my friends are counting on me!

```python
m = 'tjctf{?????????????????}'.lower()
k = '????????'.lower()

f = [[ord(k[a]) ^ ord(m[a+b]) for a in range(len(k))] for b in range(0, len(m), len(k))]
g = [a for b in f for a in b]
h = [[g[a] for a in range(b, len(g), len(f[0]))] for b in range(len(f[0]))]
i = [[h[b][a] ^ ord(k[a]) for a in range(len(h[0]))] for b in range(len(h))]
print(str([a + ord(k[0]) for b in i for a in b])[1:-1] + ',', sum([ord(a) for a in m]))
```
Original output:
```
225, 228, 219, 223, 220, 231, 205, 217, 224, 231, 228, 210, 208, 227, 220, 234, 236, 222, 232, 235, 227, 217, 223, 234, 2613
225, 228, 219, 223, 220, 231, 205, 217, 224, 231, 228, 210, 208, 227, 220, 234, 236, 222, 232, 235, 227, 217, 223, 234
```
## Solution
The objective of this challenge is to work backwards following each list comprehension's process to arrive at the final key and flag. 

### 1. Set the first byte:
- Change it until it's at the expected value
- That value: 109(m)

### 2. Reverse the final print loop
- Subtract 109 from each known target value
- Gives us a new list of values:  
`[116, 119, 110, 114, 111, 122, 96, 108, 115, 122, 119, 101, 99, 118, 111, 125, 127, 113, 123, 126, 118, 108, 114, 125]`

### 3. Reverse i values
- Group the list into 3's  
`[[116, 119, 110], [114, 111, 122], [96, 108, 115], [122, 119, 101], [99, 118, 111], [125, 127, 113], [123, 126, 118], [108, 114, 125]]`
- We know the first key value is 109
- Xor the first val of every group with 109:
`[[116, 119, 110], [114, 111, 122], [96, 108, 115], [122, 119, 101], [99, 118, 111], [125, 127, 113], [123, 126, 118], [108, 114, 125]]`  
`[[25, 119, 110], [31, 111, 122], [13, 108, 115], [23, 119, 101], [14, 118, 111], [16, 127, 113], [22, 126, 118], [1, 114, 125]]`

### 4. Reverse h
- Permutate the list based on moving each value to a new position
`0, 8, 16 | 1, 9, 17 | 2, 10, 18 | 3, 11, 19 | 4, 12, 20 | 5, 13, 21 | 6, 14, 22 | 7, 15, 23`

### 5. Reverse g
- Just flatten the list.
`[25, 31, 13, 23, 14, 16, 22, 1, 19, 111, 108, 119, 118, 127, 126, 114, 110, 122, 115, 101, 111, 113, 118, 125]`

### 6. Reverse f
- So far our first 8 values are correct, the others are not and we're just hoping it won't matter.
- Looks like the next function relies on us xoring the message with the key to produce our previous result
- Since we know the first part of the message and due the the properties of xor, we can now search though all possible values and xor until we get the desired result, and when we do, it will be a key value!
- Brute force result: `munchk`

### 7. Re-reverse i values
- Xor again, but now we know the first 3 key values so we can do all 3.
`[[116, 119, 110], [114, 111, 122], [96, 108, 115], [122, 119, 101], [99, 118, 111], [125, 127, 113], [123, 126, 118], [108, 114, 125]]`  
`[[25, 2, 0], [31, 26, 20], [13, 25, 29], [23, 2, 11], [14, 3, 1], [16, 10, 31], [22, 11, 24], [1, 7, 19]]`
- Now every value is correct!

### 7. Re-reverse h by re-permutating the list by hand...

### 8. Re-reverse g by flattening the list
`[25, 31, 13, 23, 14, 16, 22, 1, 2, 26, 25, 2, 3, 10, 11, 7, 0, 20, 29, 11, 1, 31, 24, 19]`

### 9. Re-reverse f
- Now all the values in our list are correct, fingers crossed we get something out of it...
- This final part requires use of all key values, though. Guess we'll see what happens.
- Reversed the function and this time attempted the message.
- Result: tjctf{)>oowaka48mashit',
- We're doing a fixed xor with 8 key values and 8 message values, so the final 2 values of our flag will be wrong since those are the parts we dont know
- Known message: tjctf{__oowaka__mashit__

### 10. Recover 8th key value since we know some of the plaintext
- Due to the flag format we also know there's a closing curly bracket, so we can get this part back as well. Another brute force time!
- Brute force results in just one character unknown: munchk_n

### 11. Try using our nearly-complete key...
- Result: tjctf{_ooowaka_imashit_}
- Just one unknown character! Character 7.
- Result with full key: `tjctf{_ooowakabimashitq}`

### 11. Brute force for the final key value
- We don't really have any way of finding out the final key value by playing with the xor
- We don't know the key value, and we don't know any of the corresponding message values
- So instead we'll try every combination and test it against the known correct output: 232, 235, 227 and total sum of 2613
- This gives us one message:key result, which is the flag: `tjctf{oooowakarimashita} munchkyn`