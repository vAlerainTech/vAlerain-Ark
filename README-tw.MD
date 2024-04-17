# vAlertain方舟（一種基於C++的方舟，旨在解决安全人員問題）

![](https://github.com/WhiteFoxLinux/vAlerain-Ark/blob/main/icon/icon.png)

_方舟 是 Anti-Rootkit（ 对抗恶意程序）的简写,  vAlertainArk 目标成为逆向工程师、编程人员的工具，同时也能为那些希望清理恶意软件的用户服务。 以后也将会支持更多功能和命令。_

![image](https://img.shields.io/badge/Windows-tool-blue)
![image](https://img.shields.io/badge/Windows-vAlerian-gree)
![image](https://img.shields.io/badge/Windows-Ark-blue)
![image](https://img.shields.io/badge/Windows-Ring3-gree)
![image](https://img.shields.io/badge/Windows-Ring0-gree)
![image](https://img.shields.io/badge/Windows-API-gree)

# F&Q
## 我能用你的方舟做什麼？
我的方舟現時可以實現的功能相對較少，只有管理流程和服務，以及鉤子、轉儲和其他即將實現的功能。
## 當您的功能如此先進時，您如何考慮未來？
雖然我也知道我們的功能是有限的，但它們會逐漸更新，比如通過删除PPL和防止驅動程序打開和關閉來進行創新，而且我的驅動程序寫得太垃圾了，已經準備好進行重構。
## 你開發方舟的初衷是什麼？
起初，作者喜歡使用天鵝絨劍，但後來它被取下了。 當作者正在研究Windows內核並準備編寫一個方舟來理解內核和分頁時，創建了這個項目。

## 1.0.0.2
* 優化的啟動動畫
* 支持結束、凍結和結束流程樹、查看流程路徑和複製流程資訊
* 支持複製服務名稱和註冊表資訊
* 支持讀取、查看和修改Windows文件關聯
* 支持枚舉和操作Windows服務驅動程序註冊表
* Windows消息掛鉤、滑鼠和鍵盤掛鉤測試和回檔
* 支持檢查windowsPE結構檔案分析
* 支持Windows本地代理更改

## 1.0.0.3
* 使用快照枚舉行程清單
* 使用行程ID結束行程
* 使用流程PID結束流程樹
* 能够識別流程控制碼

## 1.0.0.1
* 優化的啟動動畫
* 支持結束、凍結和結束流程樹、查看流程路徑以及複製流程的流程資訊
* 支持讀取、查看和修改Windows文件關聯
* 對Windows服務驅動程序註冊表的枚舉和操作支持
* Windows消息掛鉤、滑鼠和鍵盤的掛鉤測試和回檔
* 支持檢查windowsPE結構檔案分析
* 支持Windows本地代理更改

## v1.0.0.0

* 支持結束、凍結和結束流程樹、查看流程路徑以及複製流程的流程資訊
* 支持讀取、查看和修改Windows文件關聯
* 對Windows服務驅動程序註冊表的枚舉和操作支持
* Windows消息掛鉤、滑鼠和鍵盤的掛鉤測試和回檔
* 支持檢查windowsPE結構檔案分析
* 支持Windows本地代理更改

# 原始程式碼使用標準基於C++17
我們强烈建議使用CLion編譯，您也可以使用Microsoft的VS，但永遠不要使用dev-cpp。

# 特別感謝
* CLion的技術支援
* vAlertain開發
* SNbing54的長期評估和修復
  
