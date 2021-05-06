压缩包包含2个文件:
1、CentOS_Protective_Script.sh
2、README.txt

#############################################################################################

操作说明:
1、执行CentOS_Protective_Script.sh脚本文件进行加固,命令格式如下
   sudo sh CentOS_Protective_Script.sh
2、执行完成后,请按脚本提示重启相应服务

#############################################################################################

功能说明:
1、ALL protective			一键进行全部加固
2、Set Password Complexity Requirements 设置密码复杂度
3、Create openroot account		添加openroot账号
4、Set Remote Login Configuration(SSH)	禁止root远程登入
5、Set Shell History and TMOUT		设置history保存行数以及命令时间，设置窗口超时时间
6、Set SSH Port				更改SSH端口
7、Set Logon failure handling		登入失败处理
8、Recover Configuration		还原配置文件
9、Exit

#############################################################################################

Date:	2019-02-24
创建加固脚本，添加密码复杂度、禁止root登入、history、timeout超时、修改ssh端口，备份和还原配置文件功能

------------------------

Date:	2019-03-07
在输入ssh端口时，添加判断条件，在1024~65535之间的端口才能进一步匹配确认，否则重新输入

------------------------

Date:	2019-03-08
添加登入失败处理功能，限制登入失败三次，普通锁定5分钟，root账号锁定5分钟

------------------------

Date:	2019-03-18
添加新增openroot账号功能，防止系统没有除root账号外的其余账号，配置了禁止root远程，导致系统无法登入

----------------------

Date:	2019-03-20
新增禁止root远程登入的判断条件，可以重复执行脚本进行配置

-------------------------

Date:	2019-03-22
解决sshd_config文件在被修改过PermitRootLogin yes 后，无法判断，并直接注入PermitRootLogin no，导致配置命令冲突，无法实现禁止root远程

