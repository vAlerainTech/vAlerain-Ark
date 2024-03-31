# vAlertain方舟（一种基于C++的方舟，旨在解决安全人员问题）

![](https://github.com/WhiteFoxLinux/vAlerain-Ark/blob/main/icon/icon.png)

_方舟是Anti-Rootkit(对抗恶意程序）的简写, vAlertainArk目标成为逆向工程师、编程人员的工具，同时也能为那些希望清理恶意软件的用户服务。 以后也将会支持更多功能和命令。_

![image](https://img.shields.io/badge/Windows-tool-blue)
![image](https://img.shields.io/badge/Windows-vAlerian-gree)
![image](https://img.shields.io/badge/Windows-Ark-blue)
![image](https://img.shields.io/badge/Windows-Ring3-gree)
![image](https://img.shields.io/badge/Windows-Ring0-gree)
![image](https://img.shields.io/badge/Windows-API-gree)

#F&Q
## 我能用你的方舟做什么？
我的方舟目前可以实现的功能相对较少，只有管理流程和服务，以及钩子、转储和其他即将实现的功能。
## 当您的功能如此先进时，您如何考虑未来？
虽然我也知道我们的功能是有限的，但它们会逐渐更新，比如通过删除PPL和防止驱动程序打开和关闭来进行创新，而且我的驱动程序写得太垃圾了，已经准备好进行重构。
## 你开发方舟的初衷是什么？
起初，作者喜欢使用天鹅绒剑，但后来它被取下了。当作者正在研究Windows内核并准备编写一个方舟来理解内核和分页时，创建了这个项目。

## 1.0.0.2
* 优化的启动动画
* 支持结束、冻结和结束流程树、查看流程路径和复制流程信息
* 支持复制服务名称和注册表信息
* 支持读取、查看和修改Windows文件关联
* 支持枚举和操作Windows服务驱动程序注册表
* Windows消息挂钩、鼠标和键盘挂钩测试和回调
* 支持检查windowsPE结构文件分析
* 支持Windows本地代理更改

## 1.0.0.1
* 优化的启动动画
* 支持结束、冻结和结束流程树、查看流程路径以及复制流程的流程信息
* 支持读取、查看和修改Windows文件关联
* 对Windows服务驱动程序注册表的枚举和操作支持
* Windows消息挂钩、鼠标和键盘的挂钩测试和回调
* 支持检查windowsPE结构文件分析
* 支持Windows本地代理更改

##v1.0.0.0

* 支持结束、冻结和结束流程树、查看流程路径以及复制流程的流程信息
* 支持读取、查看和修改Windows文件关联
* 对Windows服务驱动程序注册表的枚举和操作支持
* Windows消息挂钩、鼠标和键盘的挂钩测试和回调
* 支持检查windowsPE结构文件分析
* 支持Windows本地代理更改

# 源代码使用标准基于C++17
我们强烈建议使用CLion编译，您也可以使用Microsoft的VS，但永远不要使用dev-cpp。

# 特别感谢
* CLion的技术支持
* vAlertain开发
* SNbing54的长期评估和修复
  

