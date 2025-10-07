---

layout: post
title: "Cat The Flag v2"
date: 2025-10-06 13:00:00 +0000
categories: [ctf-writeups, Cat The Flag v2]
tags: 
summary: "my writeups for picoCTF - picoGym Challenges."
author: Mensi Mohamed Amine
toc: true
math: false
comments: true
---


## compromised 

### solution 

In this task we are given an x64 elf binary, the first this i did was inspecting the executable with `file`.

![Alt Text](/assets/posts/ctf-enit-2025/compromised/1.png)

then i checked the binary mitigations using pwntools checksec utility. 

![Alt Text](/assets/posts/ctf-enit-2025/compromised/2.png)