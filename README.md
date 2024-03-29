# HuaweiBatteryControl

Control charge threshold for Huawei laptop in Windows.

华为笔记本充电控制

Tested on:
- Huawei Matebook 14 2020
- Huawei Matebook D 14 (BIOS 1.17 with --new)
- Huawei Matebook E GO
- Honor Hunter v700

## Usage:

Tips: Make sure you are using Admin permission.

```
HuaweiBatteryControl.exe <upper limit> <lower limit> [--new]
  --new    Using new methods, new devices or BIOS may require this option

HuaweiBatteryControl.exe <raw data in decimal>
  Raw data explain:
  0x<upper limit><lower limit>1003
  0x<upper limit><lower limit>48011503 (for new devices or BIOS)
  Then convert hex to decimal
```

Example:

```
PS D:\> HuaweiBatteryControl-x64.exe 70 40
Command-line arguments:
  argv[0]   d:\cli-tools\HuaweiBatteryControl-x64.exe
  argv[1]   70
  argv[2]   40
data:1177030659(0x46281003)
Connected to ROOT\WMI WMI namespace
u8Output:0

PS D:\> HuaweiBatteryControl-x64.exe 1177030659
Command-line arguments:
  argv[0]   d:\cli-tools\HuaweiBatteryControl-x64.exe
  argv[1]   1177030659
data:1177030659(0x46281003)
Connected to ROOT\WMI WMI namespace
u8Output:0
```

## Detail (in Chinese):

<https://blog.acedroidx.top/HuaweiBatteryControl/>
