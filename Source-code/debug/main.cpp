#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <cmath>
#include <stdio.h>
#include <tchar.h>
#include "Hook.h"
#include "Process.h"
#include <direct.h>
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

void COLOR_PRINT_Poc(const char* s, int color)
{
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    printf(s);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}

void COLOR_PRINT(const char* s, int color)
{
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    printf(s);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
}
/*0 = ��ɫ 8 = ��ɫ
1 = ��ɫ 9 = ����ɫ
2 = ��ɫ 10 = ����ɫ
3 = ǳ��ɫ 11 = ��ǳ��ɫ
4 = ��ɫ 12 = ����ɫ
5 = ��ɫ 13 = ����ɫ
6 = ��ɫ 14 = ����ɫ
7 = ��ɫ 15 = ����ɫ*/

#include <vector>

namespace ArkProcess {
    int Get_all_processes(int num);
    bool TerminateProcessByID(DWORD processID);
    void TerminateProcessTree(DWORD parentPID);
    wchar_t GetProcessRoute(DWORD processID);
}

int ArkProcess::Get_all_processes(int num) { // һ�������������ƻ�ȡƵ��
    while (true) {
        // �������̿���
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            cerr << "Failed to create process snapshot." << endl;
            return 1;
        }

        // ���������б�
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32)) {
            cerr << "Failed to retrieve process information." << endl;
            CloseHandle(hSnapshot);
            return 1;
        }

        cout << "Process List:" << endl;

        do {
            string processIDStr = to_string(pe32.th32ProcessID);
            string exeFileName(pe32.szExeFile);
            string result = "Process ID: " + processIDStr + ", Name: " + exeFileName;
            const char* charArray = result.c_str();
            COLOR_PRINT_Poc(charArray,3);

            // �򿪽��̾��
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                string temp_=", Handle: " + to_string(reinterpret_cast<uintptr_t>(hProcess));
                const char* charHandle = temp_.c_str();
                COLOR_PRINT_Poc(charHandle,3);
                // �رս��̾��
                CloseHandle(hProcess);
            } else {
                cerr << "Failed to open process with ID: " << pe32.th32ProcessID << endl;
            }

            cout << endl;
        } while (Process32Next(hSnapshot, &pe32));

        // �رս��̿��վ��
        CloseHandle(hSnapshot);
        Sleep(num);
    }
    return 0;
}

bool ArkProcess::TerminateProcessByID(DWORD processID) {
    // �򿪽��̾��
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        cerr << "Failed to open process handle." << endl;
        return false;
    }

    // ��������
    if (!TerminateProcess(hProcess, 0)) {
        cerr << "Failed to terminate process." << endl;
        CloseHandle(hProcess);
        return false;
    }

    // �رս��̾��
    CloseHandle(hProcess);
    return true;
}

// ����ָ�����̼����ӽ���
void ArkProcess::TerminateProcessTree(DWORD parentPID) {
    // �򿪸����̾��
    HANDLE hParentProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, parentPID);
    if (hParentProcess == NULL) {
        cerr << "Failed to open parent process handle." << endl;
        return;
    }

    // ö�ٸ����̵������ӽ���
    vector<DWORD> childPIDs;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ParentProcessID == parentPID) {
                    // �ӽ���
                    childPIDs.push_back(pe32.th32ProcessID);
                    // �ݹ�����ӽ��̵��ӽ���
                    TerminateProcessTree(pe32.th32ProcessID);
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // ���������ӽ���
    for (DWORD childPID : childPIDs) {
        HANDLE hChildProcess = OpenProcess(PROCESS_TERMINATE, FALSE, childPID);
        if (hChildProcess != NULL) {
            TerminateProcess(hChildProcess, 0);
            CloseHandle(hChildProcess);
        }
    }

    // ����������
    TerminateProcess(hParentProcess, 0);
    CloseHandle(hParentProcess);
}

int hwnd_to_int(HWND hwnd)
{
    return reinterpret_cast<intptr_t>(hwnd); //hwndת��int
}

HWND int_to_hwnd(int parameter)
{
    return reinterpret_cast<HWND>(parameter);
}

#include <psapi.h>

HWND temp1 = GetForegroundWindow(); //��ȡ���ھ��api

void window_hwnd_control(int parameter,int window_hwnd)
{
    //
    if(parameter == 1){
        //���ͽ���������Ϣ
        SendMessage(int_to_hwnd(window_hwnd), WM_SYSCOMMAND, SC_CLOSE, 0);
        COLOR_PRINT("[-]Successfully closed window message\n",3);
    }
}

const TCHAR* envVarStrings[] =
        {
                TEXT("OS         = %OS%"),
                TEXT("PATH       = %PATH%"),
                TEXT("HOMEPATH   = %HOMEPATH%"),
                TEXT("TEMP       = %TEMP%")
        };
#define  ENV_VAR_STRING_COUNT  (sizeof(envVarStrings)/sizeof(TCHAR*))
#define INFO_BUFFER_SIZE 32767
TCHAR  infoBuf[INFO_BUFFER_SIZE] = {'\0'};
void printError(const TCHAR* msg );

void GetInfoSys()
{
    DWORD i = 0;
    DWORD  bufCharCount = INFO_BUFFER_SIZE;

    // Get and display the name of the computer.
    if( !::GetComputerName( infoBuf, &bufCharCount ) )
        printError( TEXT("GetComputerName") );
    _tprintf( TEXT("\nComputer name:      %s"), infoBuf );

    // Get and display the user name.
    bufCharCount = INFO_BUFFER_SIZE;
    if( !::GetUserName( infoBuf, &bufCharCount ) )
        printError( TEXT("GetUserName") );
    _tprintf( TEXT("\nUser name:          %s"), infoBuf );

    // Get and display the system directory.
    if( !::GetSystemDirectory( infoBuf, INFO_BUFFER_SIZE ) )
        printError( TEXT("GetSystemDirectory") );
    _tprintf( TEXT("\nSystem Directory:   %s"), infoBuf );

    // Get and display the Windows directory.
    if( !::GetWindowsDirectory( infoBuf, INFO_BUFFER_SIZE ) )
        printError( TEXT("GetWindowsDirectory") );
    _tprintf( TEXT("\nWindows Directory:  %s"), infoBuf );

    // Expand and display a few environment variables.
    _tprintf( TEXT("\n\nSmall selection of Environment Variables:") );
    for( i = 0; i < ENV_VAR_STRING_COUNT; ++i )
    {
        bufCharCount = ::ExpandEnvironmentStrings(envVarStrings[i], infoBuf,
                                                  INFO_BUFFER_SIZE );
        if( bufCharCount > INFO_BUFFER_SIZE )
            _tprintf( TEXT("\n\t(Buffer too small to expand: \"%s\")"),
                      envVarStrings[i] );
        else if( !bufCharCount )
            printError( TEXT("ExpandEnvironmentStrings") );
        else
            _tprintf( TEXT("\n   %s"), infoBuf );
    }
    _tprintf( TEXT("\n\n"));
}

void printError(const TCHAR* msg )
{
    TCHAR sysMsg[MAX_PATH] = {'\0'};
    TCHAR* p = sysMsg;
    DWORD eNum = ::GetLastError();

    ::FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                     nullptr, eNum,
                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     sysMsg, MAX_PATH, nullptr );

    // Trim the end of the line and terminate it with a null
    // 9 - \t (horizontal tab)
    // [0 - 32) - All characters in this area excepting 9
    // 46 - . (dot)
    while (*p++)
    {
        if ((*p != 9 && *p < 32) || *p == 46)
        {
            *p = 0;
            break;
        }
    }

    // Display the message
    _tprintf( TEXT("\n\t%s failed with error %d (%s)"), msg, eNum, sysMsg );

    p = nullptr;
}

int main() {
    COLOR_PRINT("   _    _                _               _         _\n", 3);
    COLOR_PRINT("__   __/ \\  | | ___ _ __ __ _(_)_ __         / \\   _ __| | __\n", 3);
    COLOR_PRINT("\\ \\ / / _ \\ | |/ _ \\ '__/ _` | | '_ \\ _____ / _ \\ | '__| |/ /\"\n", 3);
    COLOR_PRINT(" \\ V / ___ \\| |  __/ | | (_| | | | | |_____/ ___ \\| |  |   < \n", 3);
    COLOR_PRINT("  \\_/_/   \\_\\_|\\___|_|  \\__,_|_|_| |_|    /_/   \\_\\_|  |_|\\_\\ \n", 3);
    bool cmd = false;
    string pc = "PC vAlerain-Ark>";
    string memu = "\nvAlerain ARK menu\n [*]Enter GetProcessList to obtain the process list"
                  "\n    [*]Enter EndProcess to end the process"
                  "\n    [*]Enter EndProcessTree to end the process tree "
                  "\n [*]Enter GetWindowMessageManagement to obtain window message management"
                  "\n  [*]Enter GetMouseWindowHandle to obtain the window handle where the mouse is located"
                  "\n[*]Enter GetTime get system time"
                  "\n[*]Input CMD to obtain simulated CMD terminal"
                  "\n[+]Monitoring keyboard hook;Enter Hook_keyboard;"
                  "\n[+]Monitor output, mouse hook input Hook_mouse;"
                  "\n[&]Enter 'new' to create a new project;"
                  "\n[*]Enter about to obtain information about"
                  "\n [*]Enter exit to exit\n";
    COLOR_PRINT(memu.c_str(), 4);
    while (true) {
        string input = "";

        COLOR_PRINT(pc.c_str(), 1);
        getline(std::cin, input);

        if (input == "GetProcessList" && cmd == false) {
            string input_proce = "";
            cout << "Input frequency to control the speed of the acquisition process in milliseconds:";
            getline(std::cin, input_proce);
            ArkProcess::Get_all_processes(stoi(input_proce)); //Ϊ�˽��getlineֻ�ܶ�ȡ�ַ�����ԭ��ʹ��stoi��������
        } else if (input == "about" && cmd == false) {
            COLOR_PRINT("\nCLion's technical support\n"
                        "vAlerain Develop;Code from Mr. vAlerain;\n"
                        "Long term evaluation and repair of SNbing54\n"
                        "Version: 1.0.0.7 (debugging)\n\n", 1);
        } else if (input == "exit" && cmd == false) {
            return 0;
        } else if (input == "EndProcess" && cmd == false) {
            DWORD processID;
            cout << "\nEnter the process ID to end the process:";
            cin >> processID;
            ArkProcess::TerminateProcessByID(processID);
        } else if (input == "EndProcessTree" && cmd == false) {
            DWORD processID_;
            cout << "Enter process PID to end the process:";
            cin >> processID_;
            ArkProcess::TerminateProcessTree(processID_);
        } else if (input == "" && cmd == false) {
            COLOR_PRINT("\nWarning: Your input of empty data cannot be parsed!\n\n", 6);
        } else if (input == "memu" && cmd == false) {
            COLOR_PRINT(memu.c_str(), 4);
        } else if (input == "GetMouseWindowHandle" && cmd == false) {
            Sleep(3000);
            cout << "[-]" << hwnd_to_int(GetForegroundWindow()) << "\n";
        } else if (input == "test-debug" && cmd == false) {
            int hWnd = 0;
            COLOR_PRINT("Input Test Window Handle:", 3);
            cin >> hWnd;
            window_hwnd_control(1, hWnd);
        } else if (input == "get-prx" && cmd == false) {
            // �������̿���
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                std::cerr << "Failed to create process snapshot." << std::endl;
                return 1;
            }

            // ���������б�
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
                const char *charArray = result.c_str();
                COLOR_PRINT(charArray, 3);

                // �򿪽��̾��
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    string temp_ = ", Handle: " + to_string(reinterpret_cast<uintptr_t>(hProcess));
                    const char *charHandle = temp_.c_str();
                    COLOR_PRINT(charHandle, 3);
                    // �رս��̾��
                    CloseHandle(hProcess);
                } else {
                    std::cerr << "Failed to open process with ID: " << pe32.th32ProcessID << std::endl;
                }

                std::cout << std::endl;
            } while (Process32Next(hSnapshot, &pe32));

            // �رս��̿��վ��
            CloseHandle(hSnapshot);

        } else if (input == "GetWindowMessageManagement" && cmd == false) {
            COLOR_PRINT("Kill Window:", 4);
            string hwnd_temp = "";
            getline(std::cin, hwnd_temp);
            window_hwnd_control(1, stoi(hwnd_temp));
        } else if (input == "GetTime" && cmd == false) {
            SYSTEMTIME temp;
            GetLocalTime(&temp);
            printf("%04d/%02d/%02d %02d:%02d:%02d\n\n", temp.wYear, temp.wMonth, temp.wDay, temp.wHour, temp.wMinute,
                   temp.wSecond);

        } else if (input == "CMD" && cmd == false) {
            COLOR_PRINT("Using CMD mode requires a restart to recover!\n",4);

            pc = "PC vAlerain-Ark(CMD)>";
            cmd = true;
        } else if (input == "GetInfo" && cmd == false) {
            GetInfoSys();
        } else if (input == "Hook_keyboard") {
            Hook_keyboard();
        }else if(input == "Hook_mouse"){
            mouseHook_();
        } else if (cmd == true) {
            system(input.c_str());
        }else if(input == "new"){
            COLOR_PRINT("Input ss for static analysis;\nInput t for dynamic analysis;\n",4);
            string input = "";
            getline(std::cin, input);
            COLOR_PRINT("Is the program 64 bit?(y/n)\n",4);
            string bit= "";
            getline(std::cin, bit);
            COLOR_PRINT("Do you need to check if the program has a shell added?(y/n)\n",4);
            string confound = "";
            getline(std::cin, confound);
            if(confound=="y"){
                const int MAXPATH = 250;
                char buffer[MAXPATH];
                getcwd(buffer, MAXPATH);
                string temp_open=buffer;
                temp_open=temp_open+"\\die_x86\\die.exe";
                system(temp_open.c_str());
            }
            if(input == "t" && bit == "y"){
                const int MAXPATH = 250;
                char buffer[MAXPATH];
                getcwd(buffer, MAXPATH);
                string temp_open=buffer;
                temp_open=temp_open+"\\IDA_Pro_7.7\\ida64.exe";
                system(temp_open.c_str());
            }else if(input == "t"){
                const int MAXPATH = 250;
                char buffer[MAXPATH];
                getcwd(buffer, MAXPATH);
                string temp_open=buffer;
                temp_open=temp_open+"\\IDA_Pro_7.7\\ida.exe";
                system(temp_open.c_str());
            }//ida.exe
            if(input == "ss" && bit =="y"){
                const int MAXPATH = 250;
                char buffer[MAXPATH];
                getcwd(buffer, MAXPATH);
                string temp_open=buffer;
                temp_open=temp_open+"\\x64dbg\\release\\x64\\x64dbg.exe";
                system(temp_open.c_str());
            }else if(input == "ss"){
                const int MAXPATH = 250;
                char buffer[MAXPATH];
                getcwd(buffer, MAXPATH);
                string temp_open=buffer;
                temp_open=temp_open+"\\x64dbg\\release\\x32\\x32dbg.exe";
                system(temp_open.c_str());
            }
        } else {
            if (cmd == false) {
                COLOR_PRINT("\nError: You entered an incorrect parameter that cannot be parsed into any data!\n\n", 4);
            }
        }
    }
}