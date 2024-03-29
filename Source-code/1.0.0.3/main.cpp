#include <iostream>
#include<windows.h>
#include <fstream>
#include <vector>

/*
        _    _                _               _         _
__   __/ \  | | ___ _ __ __ _(_)_ __         / \   _ __| | __
\ \ / / _ \ | |/ _ \ '__/ _` | | '_ \ _____ / _ \ | '__| |/ /
 \ V / ___ \| |  __/ | | (_| | | | | |_____/ ___ \| |  |   <
  \_/_/   \_\_|\___|_|  \__,_|_|_| |_|    /_/   \_\_|  |_|\_\

*/

void COLOR_PRINT(const char* s, int color)
{
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | color);
    printf(s);
    SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY | 7);
} //一坨答辩
/*0 = 黑色 8 = 灰色
1 = 蓝色 9 = 淡蓝色
2 = 绿色 10 = 淡绿色
3 = 浅绿色 11 = 淡浅绿色
4 = 红色 12 = 淡红色
5 = 紫色 13 = 淡紫色
6 = 黄色 14 = 淡黄色
7 = 白色 15 = 亮白色*/

int main() {
    COLOR_PRINT("        _    _                _               _         _\n", 3);
    COLOR_PRINT("__   __/ \\  | | ___ _ __ __ _(_)_ __         / \\   _ __| | __\n", 3);
    COLOR_PRINT("\\ \\ / / _ \\ | |/ _ \\ '__/ _` | | '_ \\ _____ / _ \\ | '__| |/ /\"\n", 3);
    COLOR_PRINT(" \\ V / ___ \\| |  __/ | | (_| | | | | |_____/ ___ \\| |  |   < \n", 3);
    COLOR_PRINT("  \\_/_/   \\_\\_|\\___|_|  \\__,_|_|_| |_|    /_/   \\_\\_|  |_|\\_\\ \n", 3);

    // 1. 读取.exe文件并转换为二进制数据
    std::ifstream file("Ark.exe", std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open the file." << std::endl;
        return 1;
    }

    std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});

    // 2. 将二进制数据存储到char数组中
    const char* exeData = buffer.data();
    size_t exeSize = buffer.size();

    // 输出char数组的大小
    std::cout << "Size of exeData: " << exeSize << std::endl;

    // 3. 将数据写回到文件中
    std::ofstream outputFile("output.exe", std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to create the output file." << std::endl;
        return 1;
    }

    // 将二进制数据写入输出文件
    outputFile.write(exeData, exeSize);

    // 关闭文件流
    outputFile.close();
    std::cout << "Data has been written to output.exe." << std::endl;
    /*
    std::ifstream file_("Ark.exe", std::ios::binary);
    std::vector<char> exeData_((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // 将vector<char>转换为char数组
    char* exeCharArray = exeData_.data();
    int dataSize = exeData_.size();


    for (int i = 0; i < dataSize; ++i) {
        std::cout << exeCharArray[i];
    }*/

    COLOR_PRINT("Starting vAlerain, enabling permissions and initialization\n",4);
    COLOR_PRINT("[*]We will import a test certificate to test the driver\n",4);

    system("Ark.exe");
    return 0;
}
