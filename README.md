# Linux 系统配置检测与基线加固脚本

## 概述

### 1. 背景
本标准规定了CENTOS 7.X操作系统主机应当遵循的操作系统安全性设置标准  
为了简化系统加固的工作, 编写了系统安全检测脚本与系统加固脚本,符合三级等保要求	  

### 2. 注意事项
由于修改系统默认配置的影响不确定性, 检测脚本与加固脚本采用不同覆盖度的操作
> 检测脚本 : 按照系统加固配置基线文档全覆盖检测
>
> 加固脚本: 只设置影响性确定不会影响系统正常使用的配置,无法确定影响性的配置项需要操作者根据检测脚本的结果进行判断, 手动进行处理, 并做好记录, 发送邮件给相关人员
>
> 检测结果： 运行脚本将结果输出到同级目录的res_system_check.txt文件中，脚本结果需要人为检查。

### 3. 适用系统版本
此脚本只适合linux分支中的redhat、centos，

# 功能列表
## 1. 检查功能
- 系统基本信息
- 资源使用情况
- 系统安全基线检测列表    
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
- 系统加固列表     
    1.ALL protective  
      一键进行全部加固       
    2.Set Password Complexity Requirements   
      设置密码有效期、复杂度、删除空密码账号     
    3.Create eproot account     
      添加eproot账号    
    4.Set Remote Login Configuration(SSH)    
      远程登录禁止root远程登入、使用ssh2协议、禁用dns解析、关闭GSSAPIAuthentication登录认证、关闭cbc分组加密      
    5.Set Shell History and TMOUT          
      设置history保存行数以及命令时间，设置窗口超时时间       
    6.Set SSH Port      
      更改SSH端口                      
    7.Set Logon failure handling         
      登录失败三次锁定600s           
    8.Recover Configuration     
      还原配置文件为系统默认初始化配置           
    9.Set kernel parameters        
      设置内核参数：屏蔽ip重定向、禁止任何人拉起cron任务     
    10.Set other    
       其他：禁用ftp、telnet、设置banner信息相关文件权限为644  
    0.exit   
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
sudo sh CentOS_Reinforce.sh  
```
