---

layout: post
title: "Forensics"
date: 2025-09-22 13:00:00 +0000
categories: [ctf-writeups, picoCTF - picoGym Challenges]
tags: [jekyll, chirpy, static-site, tutorial]
summary: "my ctf writeups."
author: Amine
toc: true
math: false
comments: true
---

## Investigative Reversing 2
### description 

![Alt Text](/assets/posts/pico-ctf/digital-forensics/investigative-reversing-2/1.png)

### solution

In this task we are given an ELF binary `mystery` and a .bmp image `encoded.bmp`. 
the first thing i did is opening the binary with `IDA pro` to perform some static analysis on the decompiled code.

**main function from IDA pro**
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char ptr; // [rsp+1Ah] [rbp-76h] BYREF
  char v5; // [rsp+1Bh] [rbp-75h]
  int v6; // [rsp+1Ch] [rbp-74h]
  int i; // [rsp+20h] [rbp-70h]
  int j; // [rsp+24h] [rbp-6Ch]
  int k; // [rsp+28h] [rbp-68h]
  int v10; // [rsp+2Ch] [rbp-64h]
  int v11; // [rsp+30h] [rbp-60h]
  int v12; // [rsp+34h] [rbp-5Ch]
  FILE *FILE_ptr_flag; // [rsp+38h] [rbp-58h]
  FILE *FILE_ptr_original; // [rsp+40h] [rbp-50h]
  FILE *v15; // [rsp+48h] [rbp-48h]
  _BYTE v16[56]; // [rsp+50h] [rbp-40h] BYREF
  unsigned __int64 v17; // [rsp+88h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  v10 = 0;
  FILE_ptr_flag = fopen("flag.txt", "r");
  FILE_ptr_original = fopen("original.bmp", "r");
  v15 = fopen("encoded.bmp", "a");
  if ( !FILE_ptr_flag )
    puts("No flag found, please make sure this is run on the server");
  if ( !FILE_ptr_original )
    puts("original.bmp is missing, please run this on the server");
  v6 = fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
  v11 = 2000;
  for ( i = 0; i < v11; ++i )
  {
    fputc(ptr, v15);
    v6 = fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
  }
  v12 = fread(v16, 0x32uLL, 1uLL, FILE_ptr_flag);
  if ( v12 <= 0 )
  {
    puts("flag is not 50 chars");
    exit(0);
  }
  for ( j = 0; j <= 49; ++j )
  {
    for ( k = 0; k <= 7; ++k )
    {
      v5 = codedChar(k, v16[j] - 5, ptr);
      fputc(v5, v15);
      fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
    }
  }
  while ( v6 == 1 )
  {
    fputc(ptr, v15);
    v6 = fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
  }
  fclose(v15);
  fclose(FILE_ptr_original);
  fclose(FILE_ptr_flag);
  return 0;
}
```

**codedChar function from IDA pro** 

```c
__int64 __fastcall codedChar(int a1, char a2, char a3)
{
  char v4; // [rsp+4h] [rbp-18h]

  v4 = a2;
  if ( a1 )
    v4 = a2 >> a1;
  return v4 & 1 | a3 & 0xFEu;
}
```

what the binary actually does is : 

**1. FILE SETUP**
```c
FILE_ptr_flag = fopen("flag.txt", "r");
FILE_ptr_original = fopen("original.bmp", "r");
v15 = fopen("encoded.bmp", "a");
if ( !FILE_ptr_flag )
    puts("No flag found, please make sure this is run on the server");
if ( !FILE_ptr_original )
    puts("original.bmp is missing, please run this on the server");
```
opens the three files, `flag.txt`, `original.bmp` and `encoded.bmp`.


**2. Copy first 2000 bytes unchanged**
```c
v6 = fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
v11 = 2000;
for ( i = 0; i < v11; ++i )
{
    fputc(ptr, v15);
    v6 = fread(&ptr, 1uLL, 1uLL, FILE_ptr_original);
}
```
reads 2000 bytes (v11 = 2000) from the original BMP and immediately writes them into the encoded BMP this preserves headers & some pixel data so the image looks valid.

**3. Read flag (50 chars expected)**
```c
v12 = fread(v16, 0x32uLL, 1uLL, FILE_ptr_flag);
if ( v12 <= 0 )
{
    puts("flag is not 50 chars");
    exit(0);
}
```
