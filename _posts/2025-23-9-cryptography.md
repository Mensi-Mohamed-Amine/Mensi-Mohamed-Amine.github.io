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
