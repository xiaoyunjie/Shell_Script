# Linux 系统检测和加固脚本 (如果对你有帮助，请来一波star)

**主要是为了Linux系统的安全，通过脚本对Linux系统进行一键检测和一键加固**

## Check_Script

```bash
#包含2个文件
CentOS_Check_Script.sh
README.txt
```

**操作说明**

```bash
#执行CentOS-Check_Script.sh脚本文件进行检查,命令格式如下
sudo sh CentOS_Check_Script.sh | tee check_`date +%Y%m%d_%H%M%S`.txt
```

**检查说明**

此脚本是按三级等保要求，编写的一键检查脚本，此脚本只适合linux分支中的redhat、centos，运行脚本将结果输出到自定义的文件中，脚本结果需要人为检查。

此检查脚本包含以下几块内容：
- 系统基本信息
- 资源使用情况
- 系统用户情况
- 身份鉴别安全
- 访问控制安全
- 安全审计
- 剩余信息保护
- 入侵防范安全
- 恶意代码防范
- 资源控制安全


----

## Protective_Script

```bash
#包含2个文件
CentOS_Protective_Script.sh
README.txt
```

**操作说明**
```bash
#执行CentOS_Protective_Script.sh脚本文件进行加固,命令格式如下
sudo sh CentOS_Protective_Script.sh
#执行完成后,请按脚本提示重启相应服务
```

**功能说明**
-  一键进行全部加固
-  设置密码复杂度
-  添加openroot账号
-  禁止root远程登入
-  设置history保存行数以及命令时间，设置窗口超时时间
-  更改SSH端口
-  登入失败处理
-  还原配置文件


