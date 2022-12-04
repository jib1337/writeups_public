# Leaky CBC | WACTF 2022

## Problem
Our resident cryptographic expert Steve has been tasked with ensuring our secret flag service is secured with encryption in transit.  
Despite Steve's wishes, the source code for the server has been made available for secure code review to ensure the implementation aligns with best practices. We are confident the codebase will pass the review with flying colours! Actually, we've just been informed that Steve is already clearing his desk and personal belongings.  
Are you able to review the application for implementation flaws that would lead to sensitive data disclosure from the Flag service? I think Steve left a copy of the application running on his machine at: crypto-1:8888 / crypto-1:9999 The codebase is available at: crypto-1.zip  

Code below:
```go
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// Constants used throughout the app
var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")

	blocksize   = 16
	environment = ""
)

// Padding and unpadding functions for PKCS7 - shamelessly stolen from stackoverflow!
func Unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// CBC Encryption routine
func encryptCBC(key, plaintext []byte, isProd bool) (ciphertext []byte, err error) {
	plaintext, err = pkcs7Pad(plaintext, blocksize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext = make([]byte, len(plaintext))
	iv := make([]byte, blocksize)
	// Fixed random IV in dev for testing purposes
	copy(iv, key[:blocksize])
	// Using random IV in prod for security
	if isProd {
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			panic(err)
		}
	}
	log.Println("Key: ", hex.EncodeToString(key), "; IV: ", hex.EncodeToString(iv))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)
	outdata := make([]byte, hex.EncodedLen(len(ciphertext)))

	hex.Encode(outdata, ciphertext)
	return outdata, nil
}

// Decryption routine
func decryptCBC(key, ct []byte) (plaintext []byte, err error) {
	var block cipher.Block
	ciphertext := make([]byte, hex.DecodedLen(len(ct)))
	hex.Decode(ciphertext, ct)
	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < blocksize {
		log.Println("ciphertext too short:", ciphertext)
		return
	}

	iv := ciphertext[:blocksize]
	ciphertext = ciphertext[blocksize:]
	if len(ciphertext)%blocksize != 0 {
		return nil, fmt.Errorf("invalid ct len: %v", len(ciphertext)%blocksize)
	}
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext = Unpad(ciphertext)

	return
}

// Sender formats messages for delivery via the socket
func Sender(data []byte, conn net.Conn) {
	data = append([]byte(fmt.Sprintf("(%s-ENV)Encrypted Message: ", environment)), data...)
	data = append(data, 0x0a) // add newline
	conn.Write(data)
}

// Server handles socket connections from clients
// Implements business logic
func Server(key []byte, isProd bool, conn net.Conn) {
	defer conn.Close()
	var err error

	pt := []byte("Please request the flag by typing FLAG into the console")
	ct, err := encryptCBC(key, pt, isProd)
	if err != nil {
		log.Println(err)
	}
	Sender(ct, conn)
	for {
		// handle messages from / to client
		message, _ := bufio.NewReader(conn).ReadString('\n')
		if message == "" {
			break
		}
		clientPt, err := decryptCBC(key, []byte(message))
		if err != nil {
			log.Println(err)
			continue
		}

		log.Println("Message Received:", string(clientPt))
		if string(clientPt) == "FLAG" {
			log.Println("Flag request received; Sending flag!")
			flagTxt, err := encryptCBC(key, []byte(os.Getenv(os.Getenv("ENVIRONMENT")+"FLAG")), isProd)
			if err != nil {
				log.Println(err)
				panic(err)
			}
			Sender(flagTxt, conn)
			break
		} else {
			txt, err := encryptCBC(key, []byte("Sorry, request not recognised. Please type FLAG if you want the flag."), isProd)
			if err != nil {
				log.Println(err)
				panic(err)
			}
			Sender(txt, conn)
		}
	}
}

func main() {
	environment = os.Getenv("ENVIRONMENT")
	isProd := environment == "PROD"

	// Use separate keys in dev and prod
	// key, err := hex.DecodeString(os.Getenv(environment + "KEY"))
	key, err := hex.DecodeString(os.Getenv("DEVKEY"))
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	log.Println("Startserver", environment)

	// Listen on appropriate ports
	srv, err := net.Listen("tcp", fmt.Sprintf(":%s", os.Getenv(environment+"PORT")))
	if err != nil {
		panic(err)
	}
	log.Printf("%s Server started on %s\n", environment, os.Getenv(environment+"PORT"))
	// run loop forever (or until ctrl-c)

	for {
		// accept connection
		conn, err := srv.Accept()

		if err != nil {
			continue
		}
		go Server(key, isProd, conn)
	}
}
```

## Solution
### 1. Review servers
There are two servers - one for prod and one for dev.  
They produce similar output, however it reading the code, the IV is exposed in dev, and static across both servers. Additionally, the IV is being used as the key.
```bash
──(kali㉿kali)-[10.60.0.2]-[~/Desktop]
└─$ nc crypto-2 8888                                          
(PROD-ENV)Encrypted Message: c2b560868924ae60a19855692a7ee995f040d321d628355d69015e5fc5fb3eb5479623e0cfcc0e0fde704f40744c2bf36a3adc12334866e6528fed60bc93dea761d685cb664da463ee6de4fcaed307d4
^C
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[10.60.0.2]-[~/Desktop]
└─$ nc crypto-2 9999
(DEV-ENV)Encrypted Message: 00112233445566778899001122334455a0a42637b63a0ac6b078690ed0799c1247946f141efa96429beccbefa1b5dc35eb5b6282b36abf68525619d3cdf173db9aacc6a3c297e530c7189231313cdc51
```

### 2. Decrypt initial message
Using the IV as the key also, the dev message can be decrypted:  
https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=YTBhNDI2MzdiNjNhMGFjNmIwNzg2OTBlZDA3OTljMTI0Nzk0NmYxNDFlZmE5NjQyOWJlY2NiZWZhMWI1ZGMzNWViNWI2MjgyYjM2YWJmNjg1MjU2MTlkM2NkZjE3M2RiOWFhY2M2YTNjMjk3ZTUzMGM3MTg5MjMxMzEzY2RjNTE
```
Please request the flag by typing FLAG into the console
```
  
### 3. Encrypt the flag message and send
Encrypt the word "FLAG" under the same key and IV.  
https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,'CBC','Raw','Hex',%7B'option':'Hex','string':''%7D)&input=RkxBRw
  
Send it across, and get some more ciphertext back.
```bash
┌──(kali㉿kali)-[10.60.0.2]-[~/Desktop]
└─$ python -c "print('0011223344556677889900112233445589ccd58c14de5dd90c82b02bc3f915d0')" | nc crypto-2 9999
(DEV-ENV)Encrypted Message: 00112233445566778899001122334455a0a42637b63a0ac6b078690ed0799c1247946f141efa96429beccbefa1b5dc35eb5b6282b36abf68525619d3cdf173db9aacc6a3c297e530c7189231313cdc51
(DEV-ENV)Encrypted Message: 0011223344556677889900112233445583d541708b4b932d068f4dc22a17feecc1ccc8eff11bd2fd0e4ad09b0c009893c57581c9d8577f676ca40bb09c93ce3e306df03411821b95e696afb2e7b8768b9f53d3e3cf4cb84accda478f8cefc7ba
```

### 4. Decrypt the new message
https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=ODNkNTQxNzA4YjRiOTMyZDA2OGY0ZGMyMmExN2ZlZWNjMWNjYzhlZmYxMWJkMmZkMGU0YWQwOWIwYzAwOTg5M2M1NzU4MWM5ZDg1NzdmNjc2Y2E0MGJiMDljOTNjZTNlMzA2ZGYwMzQxMTgyMWI5NWU2OTZhZmIyZTdiODc2OGI5ZjUzZDNlM2NmNGNiODRhY2NkYTQ3OGY4Y2VmYzdiYQ
```
Note: the development server does not support FLAG delivery at this stage.
```

### 5. Get flag from prod server
```bash
┌──(kali㉿kali)-[10.60.0.2]-[~/Desktop]
└─$ python -c "print('0011223344556677889900112233445589ccd58c14de5dd90c82b02bc3f915d0')" | nc crypto-2 8888
(PROD-ENV)Encrypted Message: 08f3ab275da6dd360a25d7452afc155a97afda83454ad34857f84782a33a8ebabf53a9eb55e68b9276d245c7af18b604665f6e14d0e623851d8d5c221754c6c81795c97c20c8067eeed7f0f66b8f4043
(PROD-ENV)Encrypted Message: 8e0354af06300f6f80490d733806b640ad024b7f1650c9edbbdaeb00999e3587746f6a279c2660520148b15d614a2bf4955b96923fe1b5db216cfa9f085e5a81
```
Decrypt this ciphertext:  
https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,%7B'option':'Hex','string':'00112233445566778899001122334455'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=OGUwMzU0YWYwNjMwMGY2ZjgwNDkwZDczMzgwNmI2NDBhZDAyNGI3ZjE2NTBjOWVkYmJkYWViMDA5OTllMzU4Nzc0NmY2YTI3OWMyNjYwNTIwMTQ4YjE1ZDYxNGEyYmY0OTU1Yjk2OTIzZmUxYjVkYjIxNmNmYTlmMDg1ZTVhODE
```
EdÚT=µ@.ß.S.cjì¶The flag is: WACTF{use_a_random_iv_please}
```