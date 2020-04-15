# Linux 系统检测和加固脚本 (如果对你有帮助，请来一波star)
通过shell脚本对Linux系统进行一键检测和一键加固。此脚本是按三级等保要求，编写的一键检查脚本，此脚本只适合linux分支中的redhat、centos，运行脚本将结果输出到自定义的文件中，脚本结果需要人为检查。

# 功能列表
## 1. 检查功能
- 系统基本信息
- 资源使用情况
- 系统安全基线检测
     1.检测密码有效期设置  
     2.检测密码强度检查配置   
     3.检查空口令账号   
     4.检查账户锁定配置   
     5.检查除root之外的账户UID为0  
     6.检查环境变量包含父目录  
     7.检查环境变量包含组权限为777的目录  
     8.远程连接安全性  
     9.检查umask配置  
    10.检查重要文件和目录的权限  
    11.检查未授权的SUID/SGID文件  
    12.检查任何人都有写权限的目录  
    13.检查任何人都有写权限的文件  
    14.检查没有属主的文件  
    15.检查异常的隐藏文件  
    16.检查登录超时设置  
    17.检查ssh 和telnet运行状态  
    18.远程登录限制  
    19.检查运行的服务 
    20.检查core dump 状态    
    21.检查rsyslog状态  
    22.检查系统默认账户  
    23.检查ftp服务状态  
    24.检查内核参数   
    25.检查icmp配置    
    26.检查定时任务    
    27.检查banner信息    
    28.检查history时间戳是否配置   
    29.检查系统默认的ttl值   
    30.检查是否禁止ssh的cbc分组加密   

## 2. 加固功能
- ALL protective  
一键进行全部加固  
- Set Password Complexity Requirements  
设置密码复杂度  
- Create eproot account  
添加eproot账号  
- Set Remote Login Configuration(SSH)  
禁止root远程登入  
- Set Shell History and TMOUT  
设置history保存行数以及命令时间，设置窗口超时时间  
- Set SSH Port  
更改SSH端口  
- Set Logon failure handling  
登入失败处理  
- Recover Configuration  
还原配置文件  
- Exit  
退出


# 使用说明 
## 1. 使用检查功能
执行CentOS_Check.sh脚本进行系统安全检查
```bash
sh CentOS_Check.sh
```

## 2. 使用加固功能   
执行CentOS_Reinforce.sh脚本进行系统安全加固
```bash
sudo sh CentOS_Protective_Script.sh  
```


