# SystemEntropyScanner

**Author:** Cadell Richard Anderson  
**License:** Custom License: SystemEntropyScanner Attribution License (QAL) v1.0
**Version:** 0.1  
**Date:** July 2025

#define NOMINMAX

#include <windows.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <cmath>
#include <iomanip>
#include <string>
#include <filesystem>
#include <fileapi.h>
#include <locale>
#include <codecvt>

// Constants
constexpr size_t BLOCK_SIZE = 4096;

// Calculate Shannon entropy
double calculateEntropy(const std::vector<unsigned char>& data) {
    std::unordered_map<unsigned char, size_t> freq;
    for (unsigned char byte : data) freq[byte]++;
    
    double entropy = 0.0;
    for (const auto& [symbol, count] : freq) {
        double p = static_cast<double>(count) / data.size();
        entropy -= p * std::log2(p);
    }
    return entropy;
}

void analyzeFileEntropy(const std::wstring& filePath) {  
    FILE* fp = nullptr;  
    errno_t err = _wfopen_s(&fp, filePath.c_str(), L"rb");  
    if (err != 0 || !fp) {  
        std::wcerr << L"[-] Cannot open: " << filePath << L"\n";  
        return;  
    }  

    std::wcout << L"\n=== Entropy Analysis: " << filePath << L" ===\n";  

    size_t blockIndex = 0;  
    double totalEntropy = 0.0, minEntropy = 9.0, maxEntropy = 0.0;  
    size_t blockCount = 0;  

    std::vector<unsigned char> buffer(BLOCK_SIZE);  
    while (true) {  
        size_t bytesRead = fread(buffer.data(), 1, BLOCK_SIZE, fp);  
        if (bytesRead == 0) break;  

        buffer.resize(bytesRead);  
        double entropy = calculateEntropy(buffer);  
        totalEntropy += entropy;  
        minEntropy = std::min(minEntropy, entropy);  
        maxEntropy = std::max(maxEntropy, entropy);  

        std::wcout << L"Block " << std::setw(4) << blockIndex++ << L" | Entropy: "  
            << std::fixed << std::setprecision(4) << entropy << L" | ";  

        if (entropy < 6.5)       std::wcout << L"[NORMAL]     ";  
        else if (entropy < 7.5)  std::wcout << L"[SUSPICIOUS] ";  
        else                     std::wcout << L"[CRITICAL!]  ";  

        for (int i = 0; i < static_cast<int>(entropy * 2); ++i)  
            std::wcout << L"|";  
        std::wcout << L"\n";  

        buffer.resize(BLOCK_SIZE);  
        blockCount++;  
    }  

    fclose(fp);  

    if (blockCount == 0) {  
        std::wcerr << L"[-] No data read from file.\n";  
        return;  
    }  

    double avgEntropy = totalEntropy / blockCount;  

    std::wcout << L"\n[Summary]\n";  
    std::wcout << L"  Total Blocks:    " << blockCount << L"\n";  
    std::wcout << L"  Average Entropy: " << std::fixed << std::setprecision(4) << avgEntropy << L"\n";  
    std::wcout << L"  Min Entropy:     " << minEntropy << L"\n";  
    std::wcout << L"  Max Entropy:     " << maxEntropy << L"\n";  

    if (avgEntropy > 7.5 || maxEntropy > 7.8)  
        std::wcout << L"[!] HIGH ENTROPY DETECTED.\n";  
}

// Entry point
int main() {
    // Set console to support UTF-8 output
    SetConsoleOutputCP(CP_UTF8);
    std::ios::sync_with_stdio(false);

    wchar_t systemDrive[MAX_PATH] = { 0 };
    DWORD len = GetEnvironmentVariableW(L"SystemDrive", systemDrive, MAX_PATH);
    if (len == 0 || len > MAX_PATH) {
        std::wcerr << L"[-] Failed to detect system drive.\n";
        return 1;
    }

    std::wstring root = std::wstring(systemDrive) + L"\\";

    std::wcout << L"[+] Scanning all files on system drive: " << root << L"\n";

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
            root, std::filesystem::directory_options::skip_permission_denied)) {

            if (entry.is_regular_file()) {
                analyzeFileEntropy(entry.path().wstring());
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception while scanning: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
