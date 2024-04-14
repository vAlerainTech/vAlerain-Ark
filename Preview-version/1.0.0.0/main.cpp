#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

int main() {
    // 创建进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return 1;
    }

    // 遍历进程列表
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Failed to retrieve process information." << std::endl;
        CloseHandle(hSnapshot);
        return 1;
    }

    std::cout << "Process List:" << std::endl;
    do {
        std::cout << "Process ID: " << pe32.th32ProcessID << ", Name: " << pe32.szExeFile << std::endl;
    } while (Process32Next(hSnapshot, &pe32));

    // 关闭进程快照句柄
    CloseHandle(hSnapshot);

    return 0;
}
