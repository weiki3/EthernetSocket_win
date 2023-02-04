# EthernetSocket on windows
> 注意事项
---
### 环境准备
1. 请提前安装好 [npcap](https://npcap.com/dist/npcap-1.72.exe) 
2. 请将 **include** 文件夹添加至 visual studio **附加包含目录**
    *项目->属性->配置属性->C/C++->常规->附加包含目录*
3. 请将 **lib** 文件夹添加至 visual studio **附加库目录**
    *项目->属性->配置属性->链接器->常规->附加库目录*
4. 请在 **延迟加载的DLL** 中添加项 **wpcap.dll**
    *项目->属性->配置属性->链接器->输入->延迟加载的DLL*

---
### 预编译处理
* 预编译部分需要添加语句  
    ```#pragma comment(lib, "wpcap.lib")```

---
### 编程过程
* 先用 **ShowAllNetworkDevices.exe** 文件查询网卡名称, 如
  >  rpcap://\\\\Device\\\\NPF_{EFEF628D-DBA1-4C02-955F-01620A0FFC12}
* 与linux平台版本的差异
    1. win平台调用 **createEthernetSocket()** 函数需要额外提供 **发送网卡的mac地址** (unsigned char的6位数组)
    2. **createEthernetSocket()** 中传入 **protocol** 参数时无需调用 **hton()** 函数转换字节序