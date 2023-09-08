---
layout: single
title:  "Do u want a c0ff33?"
date:   2023-09-05 19:23:50 -0500
categories: red-team
tags: osep
permalink: /:categories/:title/

header:
  overlay_image: /images/cloudflare1/banner.png
  overlay_filter: rgba(0, 0, 0, 0.7)
  actions:
     - label: "View Code"
       url: ""  
---

A couple of days ago a company installed some new coffee machines in the office, since we have a team dedicated to cybersecurity, implementing these machines is like giving a child a toy.

## ⚠️ Disclaimer
Before continuing with the reading of the post, it is necessary to know that:
 - **At NO time were attacks made against the platform, only the static code was analyzed and the dynamic part was based on inspecting the traffic WITHOUT injecting or modifying any request.** 
- **Said that, injection attacks like: `sql`, `xml`, `xss`, `os` and brute forcing attacks are out of scope and have NOT been audited/tested.**
- **The only attack that has been carried out is a repetition of legitimate requests from time to time. At NO time was there a loss of service.** 
- **Parts have been omitted so that it cannot be replicated.**
- **The application has NOT been fully audited, as only about <2 hours were used for the audit.**

# Introduction
The really curious thing about these machines is that it is possible to place an order with the **cashphone** app. 

**Cashphone** is an application in which we will have a previously registered user and in which we will have a balance, it is possible to make deposits through **Bank Cards** or **PayPal**. 

It works on all the machines installed by the company, so with a registered user it is possible to obtain coffees and snacks from all the machines. For example: **shopping mall machines** or **hospital machines**.

The machines contain a **QR Code**, which when scanned with the application the machine is added to the user's profile. *It is also possible to add machines under the functionality of the application.*

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911201741.png" height="500" width="600" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220919114901.png" height="500" width="600" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911202107.png" height="500" width="600" /></p>

# Lab Setup
To carry out a small audit on the application, a small lab was created with the following components.
- **Rooted phone**, *MOTO G10 with Android 11*.
- **BurpSuite**.
- Few euros. (**2€**)

## Install Certificate
In order to inspect **SSL** traffic through **BurpSuite**, it is necessary to install a **certificate** in the smartphone **system context**. To do this, it is necessary to export the **burpsuite** certificate in **DER** format.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/export_burp_ca.png" height="500" width="825" /></p>

Once exported it is necessary to convert it to **PEM** format with **openssl**.
```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem |head -1
9a5ba575
mv cacert.pem <hash>.0
```

In order to install the certificate in the `/system` path, it is necessary to start the **adbd** service as **root**, by entering the `adb root` command from the mobile that I have rooted I was not able to execute this since I got the following error message: `adbd cannot run as root in production builds`. Trying commands like:
```bash
mount -o rw,remount /system
mount: '/system' not in /proc/mounts

mount -o rw,remount /
'/dev/block/dm-0' is read-only
```
They were also not valid.

To solve that error I had to mount the route as **tmpfs** and there I could already write and read in the `/system/etc/security/cacerts` path.
```bash
> adb devices
List of devices attached
ZY32C42J6R      device
> adb push 9a5ba575.0 /sdcard/Downloads/9a5ba575.0
9a5ba575.0: 1 file pushed, 0 skipped. 0.9 MB/s (1326 bytes in 0.001s)

> adb shell
$ su
whoami
root

mount -t tmpfs tmpfs /system/etc/security/cacerts
cp /sdcard/Downloads/9a5ba575.0 /system/etc/security/cacerts
ls /system/etc/security/cacerts
9a5ba575.0
cp /system/etc/security/cacerts_google/* /system/etc/security/cacerts
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Dont reboot
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911200557.png" height="500" width="600" /></p>

>[Plataform-Tools](https://dl.google.com/android/repository/platform-tools_r33.0.3-windows.zip)
>[Configure BurpSuite](https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/)

## BurpSuite Configuration
To configure **BurpSuite** and inspect the traffic of the device, I set up an access point from the laptop and when connecting from the mobile I established as *proxy* the address where **burpsuite** was listening.


<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911200056.png" height="300" width="800" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911200153.png" height="200" width="1500" /></p>
<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911200521.png" height="500" width="600" /></p>

# APP Analysis
## SAST
### APK decompiler
To perform a static analysis of an **APK**, it is necessary to *unzip* the file, since an **apk** application is actually a container which contains all the files necessary for its correct operation it is possible to tackle this task with **zip**. It is possible to download the **CashPhone 27.2.1** from the following *apkpure* link.

> [CashPhone APK](https://m.apkpure.com/cashphone/com.telerik.LogicMobile2)

Once the **APK** is *unzipped*, it is possible to see that the application is an **embedded web**, which simply contains `.js`, `.html` and `.css` files.

Investigating the structure of the application, the `assets/www/scripts/app.js` file was discovered, which contains the **main logic** of the application, which, as I mentioned before, is based on a web application, where requests are made through **JS** **ajax** functions.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911204531.png" height="500" width="825" /></p>

### CWE-259: Use of Hard-coded Password
The first *finding* was the *hardcoding* of some variables with sensitive information such as: `googleApiProjectNumber` and `ClaveComercio`. *Especially the last one which is used to calculate the signature in each post request.*

The first point to start the analysis was to discover all the *endpoints* to which requests could be sent. The first *endpoint* and used to create a user is `PutPersonaJson`, in which a **json** is sent with the `personData` variable.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911205835.png" height="500" width="825" /></p>

It is possible to see the algorithm for creating the signature in the request, which is made up of `SHA1(email + username + name + surename + password + ClaveComercio)`.

### CWE-328: Use of Weak Hash
The second *finding* takes place in the signature calculation algorithm. Which for each function *(or endpoint)* is calculated differently but in all of them, fields sent by the client are used and the *ClaveComercio* is hardcoded in the code, which means that anyone can generate a valid signature for each request. In python it would translate to:

```python
signature = hashlib.sha1()
payload = email + user + name + surname + password + self.claveComercio
signature.update(payload.encode('utf-8'))
signature = signature.hexdigest()
```

It is recommended to use another signature method, in addition to standardizing it for all requests.

## DAST
To conclude hypotheses raised during the static analysis, the application is tested.

By intercepting all the traffic of the application with **BurpSuite**, curious variables are detected when registering a user on the platform.

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911211556.png" height="500" width="825" /></p>

At first glance it seems that we can add the value of the: `balance`, `rate`, `free units` and `administrative balance` in the first request. This hypothesis is tested but without any results of exploitation.

### CWE-345: Insufficient Verification of Data Authenticity
The third *finding* is that the application does not offer any email verification method, which leads to the creation of endless anonymous accounts.

The use of a **captcha*** and an **email verification** system could prevent accounts from being created with an automated script.

### CWE-284: Improper Access Control
The fourth *finding* consists of listing all the machines of another company without the need to scan the **QR code**. This is possible thanks to the function `GetPosicionMaquinasListJson` detected in the static analysis. It is possible to list all the machines of a site, the following python code shows the hypothesis.
```python
# Sites from 100 to 105
machines = [cf.listMachines(i) for i in range(100, 110)]
for m in machines:
    print(m['Descripcion'])
    print(m['Direccion'] + m['Latitud'] + m['Longitud'])
```

<p align="center"><img src="https://raw.githubusercontent.com/alexfrancow/alexfrancow.github.io/master/images/2023-09-07-want-a-coffee/Pasted%20image%2020220911223459.png" height="500" width="825" /></p>

The separation of machines by company, or having a user associated with *x* machines, would prevent an anonymous user from listing machines of a company. It should be a function limited to the user's site. This should be limited by physical **QR code** and not give the possibility of listing all machines with a request.

### CWE-841: Improper Enforcement of Behavioral Workflow
**CVSS Base Score**: **7.1**
**CVSS v3.1 Vector**: [AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H&version=3.1)

Testing the other functions offered by the application, one that stands out is `PutTraspasoSaldoJson` used to send the balance of the wallet to the indicated machine. This is where the **PoC CoffeeStealer** comes into play.

#### PoC CoffeeStealer
This attack consists of the following.
- A **threat actor** sends the wallet to the machine, this process is kept in an infinite loop.
- The **victim** enters the cash in the machine to withdraw a coffee.
- Since the **threat actor**'s wallet is listening in on the machine, this entered money goes directly to the attacker's wallet and cannot be withdrawn after some time.

As commented in the introduction of the post, **any user has access to any machine** installed by the company, whether it is from a supermarket, a shopping center or a company. So **the attack could be launched against several machines at once**.

> See the **fourth finding** for a method of listing machines.

An option to mitigate this type of attack would be to **block the user** if he is sending the wallet more than *x* times to the machine. Or give the option to cancel the sending of the wallet from the machine, so that the client can unlock it from the attacker.

The use of this attack does not have a direct impact on the company, but it could lower its reputation since customers would stop putting money into the machines if they know that they do not return the money or keep it money.

#### Demo
<iframe width="560" height="315" src="https://www.youtube.com/embed/qcV91zAAMek" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>


### CWE-841: Improper Enforcement of Behavioral Workflow
**CVSS Base Score**: **7.1**
**CVSS v3.1 Vector**: [AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H&version=3.1)

The last finding was the modification of a user's balance, which represents a very high risk for the company. Any user could extract products for free from the machine by abusing this behavior. This vulnerability was found on the `PutVendingSaleTPVJson` endpoint.
The signature of this request is calculated based on the following algorithm.

```
signature = codigoMaquina + codigoPersona + "movil" + "A" + dinero + claveComercio
```

> The money is multiplied by 100 in this calculation and can be higher or lower.

The final payload would be similar to the following.

```json
json_data = {                        
            "CodigoTerminal": codigoMaquina,
            "CodigoPersona": codigoPersona,
            "CodigoTarjeta": "movil",
            "Fecha": date, # 2022-12-31T00:00:00
            "FormaDePago": "A",
            "Importe": dinero,
            "FormaDePago2": "",
            "Importe2": 0,
            "Autorizacion": "",
            "Secuencia": 0,
            "VersionComunicacion": 2,
            "Site": site,
            "TipoTarjeta": 4,
            "lineas": [{}],
            "Signature": signature
}
```

#### Demo
<iframe width="560" height="315" src="https://www.youtube.com/embed/D3p8bJHq0yU" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
