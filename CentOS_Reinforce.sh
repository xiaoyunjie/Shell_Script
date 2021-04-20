#!/bin/bash

#================================================================
#   Copyright (C) 2020 Sangfor Ltd. All rights reserved.
#
#   文件名称：CentOS_Reinforce.sh
#   创 建 者：suleo
#   创建日期：2020年04月21日
#   版 本 号: V1.00
#   描    述：centos系统安全加固
#
#================================================================

#########################初始变量#################################
restart_flag=1
ostype='unknow'
# 设置环境变量
path=`cat /etc/profile |grep 'PATH="$PATH:/usr/local/bin"' >/dev/null 2>&1`
if [ $? -eq 0  ];then
    echo -e "\033[1;33m System current environment variables ：\n     $PATH      \033[0m"
else
    sed -i '$a PATH="$PATH:/usr/local/bin"\nexport PATH' /etc/profile
    souce /etc/profile
fi
###########################系统类型判断############################
if [ -f /etc/redhat-release ];then
    grep -i 'centos' /etc/redhat-release > /dev/null
    if [ $? == 0 ];then
        ostype='centos'
    fi
    grep -i 'redhat' /etc/redhat-release > /dev/null
    if [ $? == 0 ];then
        ostype='redhat'
    fi
fi

if [ -f /etc/centos-release ];then
    grep -i 'centos' /etc/centos-release > /dev/null
    if [ $? == 0 ];then
        ostype='centos'
    fi
fi

    echo -e "###########################################################################################"
    echo -e "\033[1;36m	    OS type is $ostype	    \033[0m"
    echo -e "###########################################################################################"

#######################重启ssh################################
function restart_ssh(){
    if [ $restart_flag == 0 ];then
        echo -e "\033[5;31mPlease restart SSH service manully by using 'service sshd restart' or 'systemctl restart sshd'\033[0m"
        echo -e "\033[5;31mIf firewall is turned on, you need to add the specified port to the firewall rule\033[0m"
        echo -e "\033[5;31mUsage: firewall-cmd --zone=public --add-port=20022/tcp --permanent\033[0m"
    fi
}

###########################文件备份############################
function backup(){
    if [ ! -x "backup" ]; then
        mkdir backup
        cp -rf /etc/pam.d/system-auth   backup/system-auth.bak
        cp -rf /etc/pam.d/sshd    backup/sshd.bak
        cp -rf /etc/ssh/sshd_config   backup/sshd_config
        cp -rf /etc/profile   backup/profile.bak
        cp -rf /etc/login.defs     backup/login.defs.bak
        cp -rf /etc/security/limits.conf    backup/limits.conf
        cp -rf /etc/sysctl.conf     backup/sysctl.conf
        echo -e "\033[1;33m	   [success] backup config file success    \033[0m"
    else
        echo -e "\033[5;31m    [error] backup file already exist. Please rm the backup directory    \033[0m "
        exit 1
    fi
}
###########################执行备份############################
backup

###########################配置文件还原为系统默认配置############################
function recover(){
    if [ ! -x "init_config_backup" ]; then
        cp -rf init_config_backup/system-auth /etc/pam.d/system-auth
        cp -rf init_config_backup/sshd /etc/pam.d/sshd
        cp -rf init_config_backup/sshd_config /etc/ssh/sshd_config
        cp -rf init_config_backup/profile /etc/profile
        cp -rf init_config_backup/login.defs /etc/login.defs
        cp -rf init_config_backup/limits.conf /etc/security/limits.conf
        cp -rf init_config_backup/sysctl.conf /etc/sysctl.conf
        source /etc/profile
        restart_flag=0
        echo -e "\033[1;33m	   [success] 8、 Recover success	\033[0m"
    else
        echo -e "\033[5;31m    [error] 8、 Recover failure , No init_config_backup folder  \033[0m"
    fi
}

###########################口令复杂度/有效期设置、删除空密码账户(不删除用户目录)############################
function password(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	   2、 Password security :Set password validity, complexity, and detect empty password account	\033[0m"
    echo "#########################################################################################"

# 确认系统版本
    if [ -f /etc/pam.d/system-auth ] && [ -f /etc/login.defs ]
    then
        system_auth_file="/etc/pam.d/system-auth"
        login_defs_file="/etc/login.defs"
    else
        echo -e "\033[5;31m	  [error]  Doesn't support this OS	    \033[0m"
        return 1
    fi
# 1. 口令复杂度配置
    passwd_config=`grep -i "^password.*requisite.*pam_cracklib.so.*retry=3" $system_auth_file`
    if [ "$passwd_config" == "" ]
    then
        sed -i "s/^password.*requisite.*pam_pwquality\.so.*$/password requisite pam_cracklib.so retry=3 difok=5 minlen=8 lcredit=-1 dcredit=-1 ocredit=-1 type=/g" $system_auth_file
	    echo -e "\033[1;33m    [success]  密码修改重试3次机会，新密码与老密码必须有5字符不同，长度8个字符，包含小写字母至少一个，数字至少一个，特殊字符至少一个 \033[0m"
    fi

# 2. 密码有效期设置
    expiry_config=`grep -i "^PASS_MAX_DAYS.*90" $login_defs_file`
    if [ "$expiry_config" == "" ]
    then
        sed -i "s/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS  90/g" $login_defs_file
        echo -e "\033[1;33m [success] The password is set to last for 90 days \033[0m"
    fi

# 3. 检测空密码,存在则删除该账户
    for user in `awk -F: '($2 == "") { print $1 }' /etc/shadow`
    do
        if [ $user != "" ]
        then
            userdel $user
            echo -e "\033[1;33m    [success] 删除空密码账户${user} \033[0m"
        fi
    done
}

################################新增超级管理员用户################################
function create_user(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	   3、Create eproot account	\033[0m"
    echo "#########################################################################################"
    read -p "Be sure to create an eproot account?[y/n]:"
    case $REPLY in
    y)
	grep -i 'eproot' /etc/passwd
        if [ $? == 0 ];then
	    echo -e "\033[1;36m		An eproot account has been created	\033[0m"
        else
	    read -p "Please enter your password:" PASSWD
	    useradd -g root eproot;echo "$PASSWD" | passwd --stdin eproot  > /dev/null
	    if [ $? == 0 ];then
		    echo -e "\033[1;33m	[success] eproot account created successfully	    \033[0m"
		    grep -i "eproot" /etc/sudoers
		    if [ $? != 0 ];then
		        chmod u+w /etc/sudoers > /dev/null
		        sed -i '/^root.*ALL=(ALL).*$/a\eproot  ALL=(ALL)       NOPASSWD:ALL' /etc/sudoers > /dev/null
		        if [ $? == 0 ];then
			        echo -e "\033[33;1m	   [success] Permissions set success \033[0m"
		        else
			        echo -e "\033[31;5m	   [error] Permissions set failed	\033[0m"
		        fi
		        chmod u-w /etc/sudoers > /dev/null
		    else
		        echo -e "\033[1;33m	  [success] Permissions have already been set	    \033[0m"
		    fi
	    else
		    echo -e "\033[5;31m	   [error] eproot account created failed	    \033[0m"
		    exit 1
	    fi
	fi
	;;
    n)
	;;
    *)
	create_user
    esac
}


############################限制超级管理员用户登录############################
function ssh_login(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	   4、Set Remote Login Configuration(SSH)	\033[0m"
    echo "#########################################################################################"
#远程登录使用更安全的ssh2协议
    echo >> /etc/ssh/sshd_config
    grep -i '^Protocol' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "\033[31;5m    [error] Cannot to set Protocol to '2'	    \033[0m"
        else
            echo -e "\033[33;1m    [success] Set SSH Protocol to 2	    \033[0m"
         fi
    else
        echo 'Protocol 2' >> /etc/ssh/sshd_config
        echo -e "\033[33;1m	    [Success] Set SSH Protocol to 2	    \033[0m"
    fi

# 关闭无关的ssh登录项
# 1. 关闭dns解析,加快登录速度
    grep -i '^UseDNS' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^UseDNS.*$/UseDNS no/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "\033[31;5m     [error] Cannot to set UseDNS to no      \033[0m"
        else
            echo -e "\033[33;1m     [Success] Set SSH UseNDS to no       \033[0m"
        fi
    else
        echo 'UseDNS no' >> /etc/ssh/sshd_config
        echo -e "\033[33;1m     [Success: Set SSH UseDNS to no]        \033[0m"
    fi
# 2. 关闭GSSAPIAuthentication登录认证,密码登录无需这些认证
    sed -i 's/^GSSAPIAuthentication.*$/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
    if [ $? != 0 ];then
       echo -e "\033[31;5m     [Error] Cannot to set GSSAPIAuthentication to 'no'      \033[0m"
    else
       echo -e "\033[33;1m     [Success] Set SSH GSSAPIAuthentication to no        \033[0m"
    fi
# 3. 关闭cbc分组加密
    grep -i '^Ciphers' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^Ciphes.*$/Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,arcfour/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "\033[31;5m     [Error] Cannot to set UseDNS to no      \033[0m"
        else
            echo -e "\033[33;1m     [Success] Set SSH UseNDS to no        \033[0m"
        fi
    else
        echo 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,arcfour' >> /etc/ssh/sshd_config
        echo -e "\033[33;1m     [Success] Set SSH UseDNS to no        \033[0m"
    fi

# 禁止远程登录root账户
    echo "即将禁止root远程及本地登陆，请确保你已经创建其他用户可用于登陆"
    read -p "Disable root login?[y/n](Please make sure you have created at least one another account):"
    case $REPLY in
    y)
	grep -i '^PermitRootLogin no' /etc/ssh/sshd_config > /dev/null
	if [ $? == 1 ];then
            grep -i '.*PermitRootLogin yes' /etc/ssh/sshd_config >/dev/null
            if [ $? == 0 ];then
                sed -i 's/.*PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
                if [ $? != 0 ];then
                    echo -e "\033[31;5m	    [Error]  cannot to set PermitRootLogin to 'no'	\033[0m"
                else
        	        echo -e "\033[33;1m	    [success]   Disable root remote login	    \033[0m"
        	        restart_flag=0
                fi
            else
                echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
        	echo -e "\033[33;1m	    [success] Disable root remote login	    \033[0m"
                restart_flag=0
            fi
	else
	    echo -e "\033[33;1m	  [success] Already disable root remote login	\033[0m"
	fi
        local_root=`cat /etc/pam.d/login | grep 'auth required pam_succeed_if.so user != root quiet'`
        if [[ "$local_root" == "" ]];
        then
            sed -i '$a auth required pam_succeed_if.so user != root quiet' /etc/pam.d/login
            echo -e "\033[33;1m         [success] Disable root local login     \033[0m"
        else
            echo -e "\033[33;1m   [success] Already disable root local login   \033[0m"
        fi
	;;
    n)
        ;;
    *)
        ssh_login
	;;
    esac

}

####################### 关闭密码登陆,开启密钥登陆##############################
function modify_ssh(){
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    echo -e "\033[1;33m     [success] Disable password login, enable key login   \033[0m"
}

#######################配置系统历史命令操作记录和定时帐户自动登出时间################################
function set_history_tmout(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	    5、set history and login timeout	\033[0m"
    echo "#########################################################################################"
    read -p "set history size, format, and TMOUT?[y/n]:"
    case $REPLY in
    y)
#history规格设置
        grep -i "^HISTSIZE=" /etc/profile >/dev/null
        if [ $? == 0 ];then
	        #history记录保留一万条
            sed -i "s/^HISTSIZE=.*$/HISTSIZE=10000/g" /etc/profile
        else
            echo 'HISTSIZE=10000' >> /etc/profile
        fi
        echo -e "\033[1;33m	 [success] HISTSIZE has been set to 10000	    \033[0m"
#history增加操作时间与操作用户的记录
        grep -i "^export HISTTIMEFORMAT=" /etc/profile > /dev/null
        if [ $? == 0 ];then
            sed -i 's/^export HISTTIMEFORMAT=.*$/export HISTTIMEFORMAT="%F %T `whoami`"/g' /etc/profile
        else
            echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
        fi
        echo -e "\033[1;33m	[success] HISTTIMEFORMAT has been set to Number-Time-User-Command   \033[0m"
#TIME_OUT 超时设置
        grep -i "^TMOUT=" /etc/profile	> /dev/null
        if [ $? == 0 ];then
            sed -i "s/^TMOUT=.*$/TMOUT=600/g" /etc/profile
        else
            echo "TMOUT=600" >> /etc/profile
        fi
        source /etc/profile
        echo -e "\033[33;1m	    [Success] set login timeout to 600s	    \033[0m"
        ;;
    n)
        ;;
    *)
        set_history_tmout;;
    esac
}


#######################SSH端口配置################################
function ssh_port(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	    6、set ssh port	\033[0m"
    echo "#########################################################################################"
    echo "Checking dependencies......"
    rpm -qa |grep libsemanage-python > /dev/null
    if [ $? != 0 ];then
        echo "Dependencies are being installed, please wait......."
        yum -y install policycoreutils-python > /dev/null
    fi
    read -p 'change ssh port?[y/n]:'
    case $REPLY in
    y)
        read -p 'please input the new ssh port(recommend to between 1024 and 65534, please make sure the port is not in used):' port
	#验证端口是否被占用
	if [[ $port -gt 1024 && $port -lt 65535 ]];then
          netstat -tlnp|awk -v port=$port '{lens=split($4,a,":");if(a[lens]==port){exit 2}}'  >/dev/null #2>&1
          res=$?
	    if [ $res == 2 ];then
              echo -e "\033[5;31m    [error] The port $port is already in used, try again	\033[0m"
              ssh_port
	    elif [ $res == 1 ];then
		    echo -e "\033[31;5m	    [error] change ssh port error 	    \033[0m"
		    exit 1
	    else
		    #修改ssh端口
		    grep -i "^#Port " /etc/ssh/sshd_config > /dev/null
		    if [ $? == 0 ];then
		        sed -i "s/^#Port.*$/Port $port/g" /etc/ssh/sshd_config
                semanage port -a -t ssh_port_t -p tcp $port
		    else
		        grep -i "^Port " /etc/ssh/sshd_config > /dev/null
		        if [ $? == 0 ];then
			        sed -i "s/^Port.*$/Port $port/g" /etc/ssh/sshd_config
                    semanage port -a -t ssh_port_t -p tcp $port
		        else
			        echo "Port $port" >> /etc/ssh/sshd_config
		        fi
		    fi
		    echo -e "\033[33;1m	    [Success] change ssh port success	    \033[0m"
		    restart_flag=0
	    fi
	else
        echo -e "\033[31;5m	  [error]  [##The port $port is error, please input new ssh port between 1024 and 65534 ##]	    \033[0m"
	    ssh_port
        fi
        ;;
    n)
        ;;
    *)
        echo -e "\033[31;5m	  [Error] invalid input	    \033[0m"
        ssh_port
	;;
    esac
}

#######################登录失败超次数处理################################
function login(){
    echo "#########################################################################################"
    echo -e "\033[1;36m	    7、set login failure handling		\033[0m"
    echo "#########################################################################################"
    loginconfig=/etc/pam.d/sshd
    read -p 'Are you sure set login failure handling?[y/n]:'
    case $REPLY in
    y)
	grep -i "^auth.*required.*pam_tally2.so.*$" $loginconfig  > /dev/null
	if [ $? == 0 ];then
	   sed -i "s/auth.*required.*pam_tally2.so.*$/auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300/g" $loginconfig > /dev/null
    else
	   sed -i '/^#%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300' $loginconfig > /dev/null
    fi

	if [ $? == 0 ];then
	    echo -e "\033[33;1m	   [success] Logon failure handling set success	\033[0m"
	    echo -e "\033[1;33m    限制登入失败三次，普通账号锁定5分钟，root账号锁定5分钟\033[0m"
	else
	    echo -e "\033[31;5m	   [error] Logon failure handling set failed	\033[0m"
	    exit 1
	fi
	;;
    n)
	;;
    *)
	echo -e "\033[31;5m   [Error]:invalid input       \033[0m"
	login
	;;
    esac
}

#######################设置内核参数优化################################
 function set_kernel_args(){
     echo "#########################################################################################"
     echo -e "\033[1;36m     9、Set kernel parameters\n\t1.内核参数优化\n\t2.禁止任何人拉起cron任务       \033[0m"
     echo "#########################################################################################"
     kernel_parameters_config=/etc/sysctl.conf
     read -p 'Are you sure set kernel parameters?[y/n]:'
     case $REPLY in
     y)
# 屏蔽ip重定向功能
     grep -i "^net.ipv4.conf.default.send_redirects=.*$" $kernel_parameters_config  > /dev/null
     if [ $? == 0 ];then
        sed -i "s/net.ipv4.conf.default.send_redirects=.*/net.ipv4.conf.default.send_redirects=0/g" $loginconfig > /dev/null
        sed -i "s/net.ipv4.conf.default.accept_redirects=.*/net.ipv4.conf.default.accept_redirects=0/g" $loginconfig > /dev/null
     else
        echo "net.ipv4.conf.default.send_redirects=0" >> $kernel_parameters_config
        echo "net.ipv4.conf.default.accept_redirects=0" >> $kernel_parameters_config
     fi

     if [ $? == 0 ];then
         echo -e "\033[33;1m    [success] Set kernel parameters success  \033[0m"
         echo -e "\033[1;33m     屏蔽ip重定向,防止内部网络被探测\033[0m"
     else
         echo -e "\033[31;5m     [error] Set kernel parameters failed \033[0m"
         exit 1
     fi
# 禁止任何人拉起cron任务
     cron_config=`grep -i "all" /etc/cron.deny`
     if [ "$cron_config" == "" ]
     then
         echo "all" >> /etc/cron.deny
     fi
     ;;
     n)
     ;;
     *)
     echo -e "\033[31;5m    [Error] invalid input       \033[0m"
     login
     ;;
     esac
 }

 function set_other(){
    echo "#########################################################################################"
    echo -e "\033[1;36m     10、Set other \n\t1.禁用ftp\n\t2.禁用telnet\n\t3.禁止root以外用户设置banner信息      \033[0m"
    echo "#########################################################################################"
# 禁用ftp
    check_ftp=`ps -aux |grep vsftpd |grep -v "grep" |wc -l`
    if [ $check_ftp -gt 0 ]
    then
        systemctl stop vsftpd
        pkill -9 vsftpd
        if [ $? == 0 ];then
            echo -e "\033[33;1m     [success] Set disable FTP success  \033[0m"
        else
            echo -e "\033[31;5m     [error] Set disable FTP failed \033[0m"
            exit 1
        fi
    else
        echo -e "\033[33;1m     [success] FTP is disable already \033[0m"
    fi
# 禁用telnet
    check_telnet=`ps -aux |grep telnet |grep -v "grep" |wc -l`
    if [ $check_telnet -gt 0 ]
    then
        systemctl stop telnet
        chkconfig telnetd off
        if [ $? == 0 ];then
            echo -e "\033[33;1m    [success] Set disable Telnet success  \033[0m"
        else
            echo -e "\033[31;5m     [error] Set disable Telnet failed \033[0m"
            exit 1
        fi
    else
        echo -e "\033[33;1m     [success] Telnet is disable already \033[0m"
    fi
# 设置banner信息相关文件权限为644
    chmod 644 /etc/issue
    chmod 644 /etc/issue.net
    chmod 644 /etc/motd
    if [ $? == 0 ]
    then
        echo -e "\033[33;1m    [success] The permission for the banner information file has been set to 644 \033[0m"
    else
        echo -e "\033[31;5m    [error] The permission for the banner information file has been set failed \033[0m"
    fi
 }

#######################main################################
function main(){
    echo  -e "\033[1;36m
#########################################################################################
#                                        Menu                                           #
#         1:ALL protective                                                              #
#         2:Set Password Complexity Requirements                                        #
#         3:Create eproot account                                                       #
#         4:Set SSH  Login Configuration(SSH)                                           #
#         5:Set Shell History and TMOUT                                                 #
#         6:Set SSH Port                                                                #
#         7:Set Logon failure handling                                                  #
#         8:Recover Configuration                                                       #
#         9:Set kernel parameters                                                       #
#         10:Set other                                                                  #
#	  0:Exit                                                                        #
######################################################################################### \033[0m"
    read -p "Please choice[1-9]:"
    case $REPLY in
    1)
        password
	    #create_user
        ssh_login
        modify_ssh
        set_history_tmout
        ssh_port
	login
        set_kernel_args
        set_other
        restart_ssh
        ;;
    2)
        password
	;;
    3)
        create_user
	;;
    4)
        ssh_login
        modify_ssh
        restart_ssh
	;;
    5)
        set_history_tmout
	;;
    6)
        ssh_port
        restart_ssh
	;;
    7)
	login
        restart_ssh
	;;
    8)
        recover
        restart_ssh
	;;
    9)
        set_kernel_args
    ;;
    10)
        set_kernel_args
    ;;
    0)
        exit 0
	;;
    *)
        echo -e "\033[31;5m	   [error] invalid input	    \033[0m"
        main
	;;
    esac
}

######################
main
