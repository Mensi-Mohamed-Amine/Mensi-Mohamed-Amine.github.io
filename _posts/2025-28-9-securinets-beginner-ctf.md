---

layout: post
title: "SecuriNets Beginner CTF 2025"
date: 2025-09-22 13:00:00 +0000
categories: [ctf-writeups, SecuriNets Beginner CTF 2025]
tags: 
summary: "my writeups for picoCTF - picoGym Challenges."
author: Mensi Mohamed Amine
toc: true
math: false
comments: true
---

## Commitment/OSINT

### description 

![Alt Text](/assets/posts/securinets-beginner-ctf/commitment/1.png)

### solution 

This task is pretty straightforward, the challenge name `commitment` is a hint which will guide the player to look in the commit history of github repo, first he should find my github.

![Alt Text](/assets/posts/securinets-beginner-ctf/commitment/2.png)

Also i mentioned in the description that i lost my `PDFs` which is the name of the repo the ctf player should look in. 

![Alt Text](/assets/posts/securinets-beginner-ctf/commitment/3.png)

Now checking the branches we will find a branch named `flag` we has the flag as the last commit.

![Alt Text](/assets/posts/securinets-beginner-ctf/commitment/4.png)


### flag

```
Securinets{f0und_1n_l45t_c0mm17}
```



## Double Trouble/CRYPTOGRAPHY

### description 

![Alt Text](/assets/posts/securinets-beginner-ctf/double-trouble/1.png)

### solution 

In this task the ctf player in provided with a ciphertext encrypted with two ciphers.
To decrypt the flag we should dropped it in [cyberchef](https://gchq.github.io/CyberChef/).

the first part of the flag is encoded with `base92` decrypting it with reveal the the first part `Securinets{d0ub13`

![Alt Text](/assets/posts/securinets-beginner-ctf/double-trouble/2.png)

the second part is encrypted with `base64`, decrypting it will reveal the second part `_tr0ub1e_c1ph3r}`

![Alt Text](/assets/posts/securinets-beginner-ctf/double-trouble/3.png)

### flag
```
Securinets{d0ub13_tr0ub1e_c1ph3r}
```


## Dee Dee/DIGITAL FORENSICS
### description 

![Alt Text](/assets/posts/securinets-beginner-ctf/dee-dee/1.png)

### solution

In this task the ctf player is provided with a `jpg` image `Dee Dee`, to solve the challenge we should dump the image metadata using `exiftool`.

![Alt Text](/assets/posts/securinets-beginner-ctf/dee-dee/2.png)

the first thing we notice is a `base64` string embedded in the image metadata.

![Alt Text](/assets/posts/securinets-beginner-ctf/dee-dee/3.png)

i dropped the encoded string in [cyberchef](https://gchq.github.io/CyberChef/) and we got our flag :) .

![Alt Text](/assets/posts/securinets-beginner-ctf/dee-dee/4.png)

### flag

```
Securinets{d33d33_1n_th3_ex1f}
```






