# Implementing some cryptography algorithms from scratch in c

## AES-128-ECB

#### Compilation

gcc aes_128_ecb.c -o aes_128_ecb

#### Execution

Usage: ./aes_128_ecb Usage: %s [-p plaintext_filename] [-o ciphertext_filename] [-k key_filename]
Ex: ./aes_128_ecb -p plaintext.txt -o ciphertext.enc -k .my_key.key

#### Description

The aes_128_ecb.c program code is an implementation of the aes-128-ecb algorithm. 
the flags used to run the program are :

- -p : used for the plaintext to be encrypted
- -o : where the ciphertext should be encrypted
- -k : the key to use during the encryption

The plaintext file should contains the message to encrypt
Ex: 
Roughly speaking, a group is set with one operation and the corresponding inverse operation. 
If the operation is called addition, the inverse operation is subtraction; if the operation is 
multiplication, the inverse operation is division (or multiplication with the inverse element).

The key file : contains the key in they ascii character, since the program will read and convert all character into their ascii values. (note that special character like space and new line will be considered as part of the key so if your key is already 16 bytes and then you add an new the program will consider the key as 17 bytes key and raise an error since aes-128-ecb works with only 16 bytes key length.) 

Ex: 
mnake-wask-3wasd

For this example, the program will read the key in the file and store the ascii value of each character that appears in the key.
Meaning the value of the key in the program will be an array of :
{ 0x6D, 0x6E, 0x61, 0x6B, 0x65, 0x2D, 0x77, 0x61, 0x73, 0x6B, 0x2D, 0x33, 0x77, 0x61, 0x73, 0x64 }
Ascii table
m --> 0x6D
n --> 0x6E
a --> 0x61
...

The next thing, the program will start reading the plaintext in block and perform the encryption on each block 
separately as specified in aes-128-ecb encryption mode.
The PKCS#7 Padding method was selected for handling padding in case where the plaintext length is not a multiple 16 bytes (meaning the plaintext can not evenly be broken in 16 bytes block length).

The ciphertext (encrypted text) computed will be stored in the specified filename written on the flag -o
in their hexadecimal values. So during the decryption of the ciphertext, the program will load the same character and store them in an array

Example of an ciphertext:  
915b5838cea6fc3452fdf3417b6327f30600133be290c2b93c53b675f1ff4e70285c80f2b1bedac84a819e24521bb5fa7106d22c6942d531a079440514e0696aee65161d94f455d26a06db2dd9d688491a75cc1fea2e7618093ab723542f8d7d8d1e9a69266e68bcfe80e00f505c6d6f10ff7650d52a3ca7b8d006a05f07b9457f6d7d1f91127cb4b27e79f036a19351f679d04074d3291460c275bf5f7f2d9c599e141ed25b57ba2535944f1817a5375faf9fd0cf76db4be7fee459870e8d0629d833e6814cd8db0c4e503197e0e2b39dc7ad7fafa834f1e84730c064798854087c5e75dc0dfe7543b23417ead1dcbfc52920ef47a59abd577207dd692cf10bc8edb04a57c7bd9da29b4a8e39ffccac9eb3613ae3590e0e6406dcc738104455

First block value stored in the program :
{
    0x91, 0x5b, 0x58, 0x38,
    0xce, 0xa6, 0xfc, 0x34,
    0x52, 0xfd, 0xf3, 0x41,
    0x7b, 0x63, 0x27, 0xf3
};
Then the decrytion of the 1st block will be done with the key on the array above.

Note: The program will not store the ascii value represented by each character (9, 1, 5, b, 5, 8, 3, 8, ...)
instead it will store those character in group of two as ascii value: 0x91, 0x5b, 0x58, 0x38,...


Interested cryptography, look at this amazing course of Dr. Christof Paar that helped me to understand the fundamentals concepts of cryptography : https://www.youtube.com/@introductiontocryptography4223

Enjoy... 




