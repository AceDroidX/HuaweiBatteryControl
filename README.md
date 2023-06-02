# HuaweiBatteryControl

Control charge threshold for Huawei laptop in Windows.

华为笔记本充电控制

Tested on `Honor Hunter v700` and `Huawei Matebook E GO`
## Usage:
```
HuaweiBatteryControl.exe <raw data in decimal>

Example:

PS D:\> HuaweiBatteryControl-x64.exe 1177030659
Command-line arguments:
  argv[0]   d:\cli-tools\HuaweiBatteryControl-x64.exe
  argv[1]   1177030659
data:1177030659(0x46281003)
Connected to ROOT\WMI WMI namespace
u8Output:0
```

or

```
HuaweiBatteryControl.exe <upper limit> <lower limit>

Example:

PS D:\> HuaweiBatteryControl-x64.exe 70 40
Command-line arguments:
  argv[0]   d:\cli-tools\HuaweiBatteryControl-x64.exe
  argv[1]   70
  argv[2]   40
data:1177030659(0x46281003)
Connected to ROOT\WMI WMI namespace
u8Output:0
```

## Detail (in Chinese):

<https://blog.acedroidx.top/HuaweiBatteryControl/>