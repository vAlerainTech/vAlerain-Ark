#include <windows.h>
#include <iostream>
using namespace std;
HHOOK g_hhk; // 全局键盘钩子句柄


LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_KEYDOWN) {
            KBDLLHOOKSTRUCT* pkb = (KBDLLHOOKSTRUCT*)lParam;
            // 处理键盘按下事件
            cout << "Keyboard Press:" << pkb->vkCode << " Corresponding:"<<char(pkb->vkCode)<< "\n";
        }
    }
    return CallNextHookEx(g_hhk, nCode, wParam, lParam);
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