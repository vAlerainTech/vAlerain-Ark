#include <windows.h>
#include <iostream>
using namespace std;
HHOOK g_hhk; // 全局键盘钩子句柄
HHOOK mouseHook;//全局鼠标钩子

void COLOR_PRINT_(const char* s, int color)
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

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* pkb = (KBDLLHOOKSTRUCT*)lParam;
            // 处理键盘按下事件
            string cout_what="Keyboard Press:" + to_string(pkb->vkCode) +"\n";
            COLOR_PRINT_(cout_what.c_str(),6);
        }
    }
    return CallNextHookEx(g_hhk, nCode, wParam, lParam);
}

LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_MOUSEMOVE) {
        MSLLHOOKSTRUCT* pMouseStruct = (MSLLHOOKSTRUCT*)lParam;
        string what_cout="Mouse moved to (" + to_string(pMouseStruct->pt.x)  + ", " + to_string(pMouseStruct->pt.y)  + ")\n";
        COLOR_PRINT_(what_cout.c_str(),6);
    }

    return CallNextHookEx(mouseHook, nCode, wParam, lParam);
}

int Hook_keyboard() {
    g_hhk = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0); // 安装键盘钩子
    if (g_hhk == NULL) {
        cerr << "无法安装键盘钩子" << std::endl;
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) //GetMessage(&msg, NULL, 0, 0)更好的更安全的方案
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hhk); // 卸载键盘钩子
    return 0;
}

int mouseHook_() {
    mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MouseProc, GetModuleHandle(NULL), 0);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(mouseHook);

    return 0;
}