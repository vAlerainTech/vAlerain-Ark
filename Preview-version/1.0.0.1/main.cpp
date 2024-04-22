#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <Shlwapi.h>
#include <cmath>

using namespace std;

/*
MIT License

Copyright (c) 2024 vAlerian

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

void COLOR_PRINT(const char* s, int color)
{
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    printf(s);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}
/*0 = 黑色 8 = 灰色
1 = 蓝色 9 = 淡蓝色
2 = 绿色 10 = 淡绿色
3 = 浅绿色 11 = 淡浅绿色
4 = 红色 12 = 淡红色
5 = 紫色 13 = 淡紫色
6 = 黄色 14 = 淡黄色
7 = 白色 15 = 亮白色*/


int Get_all_processes(int num) { // 一个参数用来控制获取频率
    while (true) {
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
            std::cout << "Process ID: " << pe32.th32ProcessID << ", Name: " << pe32.szExeFile;

            // 打开进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                std::cout << ", Handle: " << hProcess;
                // 关闭进程句柄
                CloseHandle(hProcess);
            } else {
                std::cerr << "Failed to open process with ID: " << pe32.th32ProcessID << std::endl;
            }

            std::cout << std::endl;
        } while (Process32Next(hSnapshot, &pe32));

        // 关闭进程快照句柄
        CloseHandle(hSnapshot);
        Sleep(num);
    }
    return 0;
}

bool TerminateProcessByID(DWORD processID) {
    // 打开进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process handle." << std::endl;
        return false;
    }

    // 结束进程
    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // 关闭进程句柄
    CloseHandle(hProcess);
    return true;
}

// 结束指定进程及其子进程
void TerminateProcessTree(DWORD parentPID) {
    // 打开父进程句柄
    HANDLE hParentProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, parentPID);
    if (hParentProcess == NULL) {
        std::cerr << "Failed to open parent process handle." << std::endl;
        return;
    }

    // 枚举父进程的所有子进程
    std::vector<DWORD> childPIDs;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ParentProcessID == parentPID) {
                    // 子进程
                    childPIDs.push_back(pe32.th32ProcessID);
                    // 递归结束子进程的子进程
                    TerminateProcessTree(pe32.th32ProcessID);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // 结束所有子进程
    for (DWORD childPID : childPIDs) {
        HANDLE hChildProcess = OpenProcess(PROCESS_TERMINATE, FALSE, childPID);
        if (hChildProcess != NULL) {
            TerminateProcess(hChildProcess, 0);
            CloseHandle(hChildProcess);
        }
    }

    // 结束父进程
    TerminateProcess(hParentProcess, 0);
    CloseHandle(hParentProcess);
}

int hwnd_to_int(HWND hwnd)
{
    return reinterpret_cast<intptr_t>(hwnd); //hwnd转换int
}

HWND temp1 = GetForegroundWindow(); //获取窗口句柄api

int main() {
    COLOR_PRINT("\nvAlerain ARK menu\n [*]Enter 1 to obtain the process list\n    [*]Enter 3 to end the process\n    [*]Enter 4 to end the process tree \n [*]Enter 5 to obtain window message management\n  [*]Enter 6 to obtain the window handle where the mouse is located\n [*]Enter about to obtain information about\n [*]Enter exit to exit\n",4);
    while(true){
    string input="";
    COLOR_PRINT("PC vAlerain-Ark>",1);
    getline(std::cin,input);
    if(input == "1") {
        string input_proce="";
        cout<<"Input frequency to control the speed of the acquisition process in milliseconds:";
        getline(std::cin,input_proce);
        Get_all_processes(stoi(input_proce)); //为了解决getline只能读取字符串的原因使用stoi用来更正
    }else if(input == "about"){
        COLOR_PRINT("CLion's technical support\n"
                    "vAlerain Develop;Code from Mr. vAlerain;\n"
                    "Long term evaluation and repair of SNbing54\n",1);
        }else if(input == "exit"){
            return 0;
        }else if(input == "3"){
            DWORD processID;
            cout<<"\nEnter the process ID to end the process:";
            cin>>processID;
            TerminateProcessByID(processID);
        }else if(input =="4"){
            DWORD processID_;
            cout<<"Enter process PID to end the process:";
            cin>>processID_;
            TerminateProcessTree(processID_);
        }else if(input == ""){
            COLOR_PRINT("\nWarning: Your input of empty data cannot be parsed!\n\n",6);
        }else if(input == "memu"){
        COLOR_PRINT("\nvAlerain ARK menu\n [*]Enter 1 to obtain the process list\n    [*]Enter 3 to end the process\n    [*]Enter 4 to end the process tree \n [*]Enter about to obtain information about\n [*]Enter exit to exit\n",4);
        }else if(input == "6"){
            Sleep(3000);
            cout<<"[-]"<<hwnd_to_int(GetForegroundWindow())<<"\n";
        }else if(input == "test-cpu"){

        }else{
            COLOR_PRINT("\nError: You entered an incorrect parameter that cannot be parsed into any data!\n\n",4);
        }
    }
    return 0;
}
