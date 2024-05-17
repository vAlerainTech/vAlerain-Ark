#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
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
            string processIDStr = std::to_string(pe32.th32ProcessID);
            string exeFileName(pe32.szExeFile);
            string result = "Process ID: " + processIDStr + ", Name: " + exeFileName;
            const char* charArray = result.c_str();
            COLOR_PRINT(charArray,3);

            // 打开进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                string temp_=", Handle: " + to_string(reinterpret_cast<uintptr_t>(hProcess));
                const char* charHandle = temp_.c_str();
                COLOR_PRINT(charHandle,3);
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

HWND int_to_hwnd(int parameter)
{
    return reinterpret_cast<HWND>(parameter);
}

HWND temp1 = GetForegroundWindow(); //获取窗口句柄api

void window_hwnd_control(int parameter,int window_hwnd)
{
    //
    if(parameter == 1){
        //发送结束窗口信息
        SendMessage(int_to_hwnd(window_hwnd), WM_SYSCOMMAND, SC_CLOSE, 0);
        COLOR_PRINT("[-]Successfully closed window message\n",3);
    }
}
int main() {
    COLOR_PRINT("        _    _                _               _         _\n", 3);
    COLOR_PRINT("__   __/ \\  | | ___ _ __ __ _(_)_ __         / \\   _ __| | __\n", 3);
    COLOR_PRINT("\\ \\ / / _ \\ | |/ _ \\ '__/ _` | | '_ \\ _____ / _ \\ | '__| |/ /\"\n", 3);
    COLOR_PRINT(" \\ V / ___ \\| |  __/ | | (_| | | | | |_____/ ___ \\| |  |   < \n", 3);
    COLOR_PRINT("  \\_/_/   \\_\\_|\\___|_|  \\__,_|_|_| |_|    /_/   \\_\\_|  |_|\\_\\ \n", 3);
    bool cmd = false;
    string pc= "PC vAlerain-Ark>";
    COLOR_PRINT("\nvAlerain ARK menu\n [*]Enter 1 to obtain the process list\n    [*]Enter 3 to end the process\n    [*]Enter 4 to end the process tree \n [*]Enter 5 to obtain window message management\n  [*]Enter 6 to obtain the window handle where the mouse is located\n[*]Enter GetTime get system time\n[*]Input CMD to obtain simulated CMD terminal\n[*]Enter about to obtain information about\n [*]Enter exit to exit\n",4);
    while(true){
    string input="";

    COLOR_PRINT(pc.c_str(),1);
    getline(std::cin,input);

    if(input == "1" && cmd == false) {
        string input_proce="";
        cout<<"Input frequency to control the speed of the acquisition process in milliseconds:";
        getline(std::cin,input_proce);
        Get_all_processes(stoi(input_proce)); //为了解决getline只能读取字符串的原因使用stoi用来更正
    }else if(input == "about" && cmd == false){
        COLOR_PRINT("CLion's technical support\n"
                    "vAlerain Develop;Code from Mr. vAlerain;\n"
                    "Long term evaluation and repair of SNbing54\n"
                    "Version: 1.0.0.6 (debugging)\n",1);
        }else if(input == "exit" && cmd == false){
            return 0;
        }else if(input == "3" && cmd == false){
            DWORD processID;
            cout<<"\nEnter the process ID to end the process:";
            cin>>processID;
            TerminateProcessByID(processID);
        }else if(input =="4" && cmd == false){
            DWORD processID_;
            cout<<"Enter process PID to end the process:";
            cin>>processID_;
            TerminateProcessTree(processID_);
        }else if(input == "" && cmd == false){
            COLOR_PRINT("\nWarning: Your input of empty data cannot be parsed!\n\n",6);
        }else if(input == "memu" && cmd == false){
        COLOR_PRINT("\nvAlerain ARK menu\n [*]Enter 1 to obtain the process list\n    [*]Enter 3 to end the process\n    [*]Enter 4 to end the process tree \n [*]Enter about to obtain information about\n [*]Enter exit to exit\n",4);
        }else if(input == "6" && cmd == false){
            Sleep(3000);
            cout<<"[-]"<<hwnd_to_int(GetForegroundWindow())<<"\n";
        }else if(input == "test-debug" && cmd == false){
            int hWnd=0;
            COLOR_PRINT("Input Test Window Handle:",3);
            cin>>hWnd;
            window_hwnd_control(1,hWnd);
        }else if(input == "get-prx" && cmd == false){
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
            string processIDStr = std::to_string(pe32.th32ProcessID);
            string exeFileName(pe32.szExeFile);
            string result = "Process ID: " + processIDStr + ", Name: " + exeFileName;
            const char* charArray = result.c_str();
            COLOR_PRINT(charArray,3);

            // 打开进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                string temp_=", Handle: " + to_string(reinterpret_cast<uintptr_t>(hProcess));
                const char* charHandle = temp_.c_str();
                COLOR_PRINT(charHandle,3);
                // 关闭进程句柄
                CloseHandle(hProcess);
            } else {
                std::cerr << "Failed to open process with ID: " << pe32.th32ProcessID << std::endl;
            }

            std::cout << std::endl;
        } while (Process32Next(hSnapshot, &pe32));

        // 关闭进程快照句柄
        CloseHandle(hSnapshot);

        }else if(input == "5" && cmd == false){
            COLOR_PRINT("Kill Window:",4);
            string hwnd_temp="";
            getline(std::cin,hwnd_temp);
            window_hwnd_control(1,stoi(hwnd_temp));
        }else if(input =="GetTime" && cmd == false){
            SYSTEMTIME temp;
            GetLocalTime(&temp);
            printf("%04d/%02d/%02d %02d:%02d:%02d\n", temp.wYear, temp.wMonth, temp.wDay, temp.wHour, temp.wMinute, temp.wSecond);

        }else if(input == "CMD" && cmd == false){
            pc="PC vAlerain-Ark(CMD)>";
            cmd = true;
        }else if(cmd == true){
            system(input.c_str());
        }else{
            if(cmd == false){COLOR_PRINT("\nError: You entered an incorrect parameter that cannot be parsed into any data!\n\n",4);}
        }

    }
}
