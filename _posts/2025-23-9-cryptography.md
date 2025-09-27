---

layout: post
title: "Cryptography"
date: 2025-09-22 13:00:00 +0000
categories: [ctf-writeups, picoCTF - picoGym Challenges]
tags: [jekyll, chirpy, static-site, tutorial]
summary: "my ctf writeups."
author: Amine
toc: true
math: false
comments: true
---

## hashcrack

### description

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/1.png)

### solution

In this crypto task we are provided with a remote service.
when connecting to the remote using `netcat` we can see the following prompt, we can notice that we have a hash digest.

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/2.png)

first thing i did is identifing the hash algorithm using `hashid` :

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/3.png)

After that i used `hashcat` tool along with the famous wordlist `rockyou` to crack the hash digest.

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/4.png)

and we got the password `password123` :) 

After feeding the password to the remote service we got another hash digest, so i walked around the same earlier process.

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/5.png)

I identifier the algorithm for the second hash using `hashid` 

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/6.png)

And i used `hashcat` and `rockyou` again to crack it.

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/7.png)

After feeding the second password `letmein` to the remote we got another hash, os we will do the same steps again, `hashid` -> `hashcat` :

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/8.png)

The algorithm used for the third hash digest is `SHA-256` :

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/9.png)

After using `hashcat` with `rockyou` wordlist, we got our password `qwerty098`

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/10.png)

And feeding the password to the remote server we got our flag :)

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/11.png)

### exploit

```python
#!/usr/bin/env python3
from pwn import *
import hashlib
from typing import Optional
HOST = "verbal-sleep.picoctf.net"
PORT = 60128
io = remote(HOST, PORT)
def crack_md5(md5_hex: str, rockyou_path: str = "rockyou.txt", show_progress: bool = False) -> Optional[str]:
    """
    Try to crack an MD5 hex digest using a wordlist file (e.g. rockyou.txt).

    Parameters
    ----------
    md5_hex : str
        The target MD5 hex digest (case-insensitive).
    rockyou_path : str
        Path to the wordlist file. The file is read in binary mode.
    show_progress : bool
        If True, prints a simple counter every 100000 tries.

    Returns
    -------
    Optional[str]
        The cracked password as a string (decoded with latin-1), or None if not found.
    """
    target = md5_hex.strip().lower()
    if len(target) != 32 or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("md5_hex must be a 32-character hex string")

    try:
        with open(rockyou_path, "rb") as f:
            for i, line in enumerate(f, start=1):
                # remove newline bytes (\n or \r\n)
                pw_bytes = line.rstrip(b"\r\n")
                if not pw_bytes:
                    continue

                digest = hashlib.md5(pw_bytes).hexdigest()
                if digest == target:
                    # decode with latin-1 so bytes <-> str mapping is preserved
                    return pw_bytes.decode("latin-1")

                if show_progress and (i % 100000 == 0):
                    print(f"Checked {i:,} passwords...")

    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {rockyou_path}")
    except PermissionError:
        raise PermissionError(f"Cannot read wordlist: {rockyou_path}")

    return None
io.recvuntil(b'We have identified a hash: ')
hash_md5 = io.recvline().strip().decode()
log.success(f"hash_md5 : {hash_md5}")
pw = crack_md5(hash_md5, rockyou_path="rockyou.txt", show_progress=True)
if pw is not None:
    print("Found:", pw)
else:
    print("Not found in wordlist.")
io.sendline(pw.encode())
def crack_sha1(sha1_hex: str, rockyou_path: str = "rockyou.txt", show_progress: bool = False) -> Optional[str]:
    """
    Try to crack a SHA-1 hex digest using a wordlist file (e.g. rockyou.txt).

    Parameters
    ----------
    sha1_hex : str
        The target SHA-1 hex digest (case-insensitive, 40 hex chars).
    rockyou_path : str
        Path to the wordlist file. The file is read in binary mode.
    show_progress : bool
        If True, prints a simple counter every 100000 tries.

    Returns
    -------
    Optional[str]
        The cracked password as a string (decoded with latin-1), or None if not found.
    """
    target = sha1_hex.strip().lower()
    if len(target) != 40 or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("sha1_hex must be a 40-character hex string")

    try:
        with open(rockyou_path, "rb") as f:
            for i, line in enumerate(f, start=1):
                pw_bytes = line.rstrip(b"\r\n")
                if not pw_bytes:
                    continue

                digest = hashlib.sha1(pw_bytes).hexdigest()
                if digest == target:
                    return pw_bytes.decode("latin-1")

                if show_progress and (i % 100000 == 0):
                    print(f"Checked {i:,} passwords...")

    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {rockyou_path}")
    except PermissionError:
        raise PermissionError(f"Cannot read wordlist: {rockyou_path}")

    return None
io.recvuntil(b'Flag is yet to be revealed!! Crack this hash: ')
hash_sha1 = io.recvline().strip().decode()
log.success(f"hash_sha1 : {hash_sha1}")
pw = crack_sha1(hash_sha1, rockyou_path="rockyou.txt", show_progress=True)
if pw is not None:
    print("Found:", pw)
else:
    print("Not found in wordlist.")
io.sendline(pw.encode())
def crack_sha256(sha256_hex: str, rockyou_path: str = "rockyou.txt", show_progress: bool = False) -> Optional[str]:
    """
    Try to crack a SHA-256 hex digest using a wordlist file (e.g. rockyou.txt).

    Parameters
    ----------
    sha256_hex : str
        The target SHA-256 hex digest (case-insensitive, 64 hex chars).
    rockyou_path : str
        Path to the wordlist file. The file is read in binary mode.
    show_progress : bool
        If True, prints a simple counter every 100000 tries.

    Returns
    -------
    Optional[str]
        The cracked password as a string (decoded with latin-1), or None if not found.
    """
    target = sha256_hex.strip().lower()
    if len(target) != 64 or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("sha256_hex must be a 64-character hex string")

    try:
        with open(rockyou_path, "rb") as f:
            for i, line in enumerate(f, start=1):
                pw_bytes = line.rstrip(b"\r\n")
                if not pw_bytes:
                    continue

                digest = hashlib.sha256(pw_bytes).hexdigest()
                if digest == target:
                    return pw_bytes.decode("latin-1")

                if show_progress and (i % 100000 == 0):
                    print(f"Checked {i:,} passwords...")

    except FileNotFoundError:
        raise FileNotFoundError(f"Wordlist not found: {rockyou_path}")
    except PermissionError:
        raise PermissionError(f"Cannot read wordlist: {rockyou_path}")

    return None
io.recvuntil(b'Almost there!! Crack this hash: ')
hash_sha256 = io.recvline().strip().decode()
log.success(f"hash_sha256 : {hash_sha256}")
pw = crack_sha256(hash_sha256, rockyou_path="rockyou.txt", show_progress=True)
if pw is not None:
    print("Found:", pw)
else:
    print("Not found in wordlist.")
io.sendline(pw.encode())
io.interactive()
```

### exploit output

![Alt Text](/assets/posts/pico-ctf/cryptography/hashcrack/12.png)

### flag
```
picoCTF{UseStr0nG_h@shEs_&PaSswDs!_93e052d7}
```

## EVEN RSA CAN BE BROKEN???
challenge files @ [EVEN RSA CAN BE BROKEN???](https://github.com/Mensi-Mohamed-Amine/ctf-writeups/tree/main/picoCTF%20-%20picoGym%20Challenges/even-rsa-can-be-broken)

## description 

![Alt Text](/assets/posts/pico-ctf/cryptography/even-rsa-can-be-broken/1.png)

## solution 
We are given the source code for the challenge which is an implementation of RSA algorithm .
```python
from sys import exit
from Crypto.Util.number import bytes_to_long, inverse
from setup import get_primes

e = 65537

def gen_key(k):
    """
    Generates RSA key with k bits
    """
    p,q = get_primes(k//2)
    N = p*q
    d = inverse(e, (p-1)*(q-1))

    return ((N,e), d)

def encrypt(pubkey, m):
    N,e = pubkey
    return pow(bytes_to_long(m.encode('utf-8')), e, N)

def main(flag):
    pubkey, _privkey = gen_key(1024)
    encrypted = encrypt(pubkey, flag) 
    return (pubkey[0], encrypted)

if __name__ == "__main__":
    flag = open('flag.txt', 'r').read()
    flag = flag.strip()
    N, cypher  = main(flag)
    print("N:", N)
    print("e:", e)
    print("cyphertext:", cypher)
    exit()

```

The program encrypt the flag using RSA algorithm, so to solve this challenge we should use `sympy` library to factorize `N` and get `p` and `q` prime numbers and then calculate `phi` and finally calculate the private exponent `d` to decrypt our ciphertext.

### exploit
```python

# sympy_rsa_dec#!/usr/bin/env python3
# sympy_rsa_decrypt.py
from sympy import factorint, mod_inverse
from pwn import *
HOST = 'verbal-sleep.picoctf.net'
PORT = 59419

io = remote(HOST, PORT)

# Given values
io.recvuntil(b'N: ')
N = int(io.recvline().strip().decode())
log.success(f"N: {N}")
io.recvuntil(b'e: ')
e = int(io.recvline().strip().decode())
log.success(f"e: {e}")
io.recvuntil(b'cyphertext: ')
c = int(io.recvline().strip().decode())
log.success(f"c: {c}")

# Factor N (SymPy will return a dict {prime: exponent})
factors = factorint(N)
print("factors:", factors)

# Convert factor dict to a list of primes repeated by exponent
primes = []
for p, exp in factors.items():
    primes.extend([p] * exp)

if len(primes) != 2:
    raise SystemExit("N is not a product of exactly two primes (or SymPy didn't find it that way).")

p, q = primes
print("p =", p)
print("q =", q)

# Compute private exponent
phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)
print("d =", d)

# Decrypt
m = pow(c, d, N)
# Convert integer to bytes and decode
mb = m.to_bytes((m.bit_length() + 7) // 8, 'big')
try:
    plaintext = mb.decode()
except UnicodeDecodeError:
    plaintext = mb
print("plaintext:", plaintext)
```

### exploit output

![Alt Text](/assets/posts/pico-ctf/cryptography/even-rsa-can-be-broken/2.png)

### flag

```
picoCTF{tw0_1$_pr!m3df98b648}
```

## interencdec

challenge files @ [interencdec](https://github.com/Mensi-Mohamed-Amine/ctf-writeups/tree/main/picoCTF%20-%20picoGym%20Challenges/interendec)

### description 
![Alt Text](/assets/posts/pico-ctf/cryptography/interencdec/1.png)

### solution
In this challenge we have double base64 string, so to decrypt it i chained some bash commands to do the job, and we got what look like a ROT-X string.

![Alt Text](/assets/posts/pico-ctf/cryptography/interencdec/2.png)

Knowing the flag format `picoCTF{.*}` i mapped `p` to `w` and i figured out that the cipher is ROT19 (forward) or ROT-7 (backward), so i used the `tr` command to decrypt the cihpertext and we got our flag :)) .

![Alt Text](/assets/posts/pico-ctf/cryptography/interencdec/3.png)

### full command 

```bash
cat enc_flag | base64 -d | sed "s/b'//g" | sed "s/'//g" | base64 -d | tr 'A-Za-z' 'T-ZA-St-za-s'
```

### flag

```
picoCTF{caesar_d3cr9pt3d_ea60e00b}
```




## b00tl3gRSA2

### description

![Alt Text](/assets/posts/pico-ctf/cryptography/b00tl3gRSA2/1.png)

## solution

