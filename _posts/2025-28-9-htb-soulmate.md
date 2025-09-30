---

layout: post
title: "soulmate"
date: 2025-09-22 13:00:00 +0000
categories: [Hack The Box, machines]
tags: [jekyll, chirpy, static-site, tutorial]
summary: "my ctf writeups."
author: Amine
toc: true
math: false
comments: true
---

## reconnaissance (information gathering)

I started by running an Nmap scan.

![Alt Text](/assets/posts/htb/soulmate/1.png)

We can notice the domain `http://soulmate.htb`

## host configuration 

I dropped the domain to `/etc/hosts` :

```bash
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts
```


## web app pentesting

First i opened the domain in the browser which reveal a dating website.

![Alt Text](/assets/posts/htb/soulmate/2.png)

The website has a login and sign-up forms which can be an attack vectors to perform our black-box pentesting.
After some static analysis on the webiste i performed a sub-domain enumeration using `ffuf` along with `SecLists`. 

![Alt Text](/assets/posts/htb/soulmate/3.png)

## host configuration 

I dropped the sub-domain to `/etc/hosts` :

```bash
echo "10.10.11.86 ftp.soulmate.htb" | sudo tee -a /etc/hosts
```


The scan result showed an `ftp` subdomain so i dropped the sub-domain in the browser and we got a `CrushFTP WebInterface`.

![Alt Text](/assets/posts/htb/soulmate/4.png)



https://app.hackthebox.com/machines/Soulmate
https://infosecwriteups.com/htb-soulmate-walkthrough-ff39e0028c6a