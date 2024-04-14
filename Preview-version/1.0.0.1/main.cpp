#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <Shlwapi.h>

using namespace std;

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


int Get_all_processes(int num){ //一个参数用来控制获取频率
    while(true) {
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
        Sleep(num);
    }
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

int main() {

    while(true){
    COLOR_PRINT("vAlerain ARK menu\n [*]Enter 1 to obtain the process list\n    [*]Enter 3 to end the process\n    [*]Enter 4 to end the process tree \n [*]Enter about to obtain information about\n [*]Enter exit to exit\n",4);
    string input="";
    cin>>input;
    if(input == "1") {
        int input_proce=0;
        cout<<"Input frequency to control the speed of the acquisition process in milliseconds:";
        cin>>input_proce;
        Get_all_processes(input_proce);
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
        }
    }
    return 0;
}
