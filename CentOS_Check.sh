#!/bin/bash

 #================================================================
 #   Copyright (C) 2020 Sangfor Ltd. All rights reserved.
 #
 #   文件名称：CentOS_Check.sh
 #   创 建 者：suleo
 #   创建日期：2020年04月13日
 #   版 本 号: V1.00
 #   描    述：centos系统安全检测
 #
 #================================================================

export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
source /etc/profile

if [ `id -u` -eq 0 ];
then
    echo "##########################################################################"
    echo "#                                                                        #"
    echo "#                        Epoint health check script                      #"
    echo "#                                                                        #"
    echo "#                                 警告                                   #"
    echo "#              本脚本只是一个检查的操作,未对服务器做任何修改             #"
    echo "#                                                                        #"
    echo "##########################################################################"
    echo " "
else
    echo "请切换为root用户执行脚本!"
    exit 1
fi

exec 2>/dev/null
CN_LANG=`echo $LANG | grep CN`
date=$(date "+%Y-%m-%d %H:%M:%S")
logfile=res_centos_check.txt

if [ "$CN_LANG" == "" ];
then
    cn=true
else
    cn=false
fi

rm $logfile

log() {
    echo "$1" >> $logfile
}
log "扫描时间：${date}"

echo -e "\033[33;1m正在收集系统基本信息....\033[0m"
log ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>系统基本信息<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
hostname=$(uname -n)
system=$(cat /etc/os-release | grep "^NAME" | awk -F\" '{print $2}')
version=$(cat /etc/redhat-release | awk '{print $4$5}')
kernel=$(uname -r)
platform=$(uname -p)
address=$(ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" | awk '{ print $2; }' | tr '\n' '\t' )
cpumodel=$(cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq)
cpu=$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)
machinemodel=$(dmidecode | grep "Product Name" | sed 's/^[ \t]*//g' | tr '\n' '\t' )
date=$(date)

log "主机名:           $hostname"
log "系统名称:         $system"
log "系统版本:         $version"
log "内核版本:         $kernel"
log "系统类型:         $platform"
log "本机IP地址:       $address"
log "CPU型号:         $cpumodel"
log "CPU核数:          $cpu"
log "机器型号:         $machinemodel"
log "系统时间:         $date"
log " "
echo -e "\033[33;1m 正在收集系统资源使用情况....\033[0m"
log ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>资源使用情况<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
summemory=$(free -h |grep "Mem:" | awk '{print $2}')
freememory=$(free -h |grep "Mem:" | awk '{print $4}')
usagememory=$(free -h |grep "Mem:" | awk '{print $3}')
uptime=$(uptime | awk '{print $2" "$3" "$4" "$5}' | sed 's/,$//g')
loadavg=$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')

log "总内存大小:           $summemory"
log "已使用内存大小:       $usagememory"
log "可使用内存大小:       $freememory"
log "系统运行时间:         $uptime"
log "系统负载:             $loadavg"
log "=============================dividing line================================"
log "内存状态:"
memory_statu=$(vmstat 2 5)
log "  $memory_statu"
log "=============================dividing line================================"
log "僵尸进程:"
zombies=$(ps -ef | grep zombie | grep -v grep)
if [ $zombies == 1 ];then
    log "  无僵尸进程"
else
    log "  有僵尸进程"
    log "  请使用ps -ef | grep zombie查看"
fi
log "=============================dividing line================================"
log "耗CPU最多的进程:"
max_cpu_process=$(ps auxf |sort -nr -k 3 |head -5)
log "  $max_cpu_process"
log "=============================dividing line================================"
log "耗内存最多的进程:"
max_memory_process=$(ps auxf |sort -nr -k 4 |head -5)
log "  $max_memory_process"
log "=============================dividing line================================"
log "环境变量:"
env=$(env)
log "  $env"
log "=============================dividing line================================"
log "路由表:"
route=$(route -n)
log "  $route"
log "=============================dividing line================================"
log "监听端口:"
netstat=$(netstat -tunlp)
log "  $netstat"
log "=============================dividing line================================"
log "当前建立的连接:"
connect_status-$(netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}')
log "  $connect_status"
log "=============================dividing line================================"
log "开机启动的服务:"
log "请确认是否有非法服务开机自启,请删除该任务"
service_list=$(systemctl list-unit-files | grep enabled)
log "  $service_list"
log " "

echo -e "\033[33;1m 系统安全基线检测开始....\033[0m"
log ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>开始系统安全检查<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
<<'COMMENT' 注释此段原因：系统变为密钥登陆，禁用密码登录
# 1. 检测密码有效期设置
echo -e "\033[33;1m 1.检测密码有效期设置\033[0m"
PASS_MAX_DAYS=`cat /etc/login.defs | grep "PASS_MAX_DAYS" | grep -v \# | awk '{print$2}'`
PASS_MIN_DAYS=`cat /etc/login.defs | grep "PASS_MIN_DAYS" | grep -v \# | awk '{print$2}'`
PASS_WARN_AGE=`cat /etc/login.defs | grep "PASS_WARN_AGE" | grep -v \# | awk '{print$2}'`
if [ "$PASS_MAX_DAYS" == "99999" ];
then
    log "1.未配置密码超时时间,不安全"
    log "建议:"
    log "  执行 sed -i '/PASS_MAX_DAYS/s/99999/90/g' /etc/login.defs 设置密码的有效时间为90天"
else
    log "1.已配置密码超时时间${PASS_MAX_DAYS},安全"
fi

# 2. 检测密码强度检查配置
echo -e "\033[33;1m 2.检测密码强度检查配置 \033[0m"
FIND=`cat /etc/pam.d/system-auth | grep 'password.*requisite.*pam_cracklib.so'`
if [ "$FIND" == "" ];
then
    log "2.未配置密码强度检查,不安全"
    log "建议:"
    log "  请按照系统加固文档2.1.2 进行配置"
else
    log "2.已配置密码强度检查,安全"
fi

# 3. 检查空口令账号
echo -e "\033[33;1m 3.检查空口令账号\033[0m"
NULLF=`awk -F: '($2 == "") {print $1}' /etc/shadow`
if [ "$NULLF" != "" ];
then
    log "3.存在空密码账户,不安全"
    log "检查结果如下:"
    log "  $NULLF"
    log "建议:"
    log "  上述账户无密码,使用passwd 命令添加密码"
else
    log "3.未发现空密码账户,安全"
fi

# 4.检查账户锁定配置
echo -e "\033[33;1m 4.检查账户锁定配置 \033[0m"
FIND=`cat /etc/pam.d/sshd | grep 'auth.*required.*pam_tally2.so'`
if [ "$FIND" == "" ];
then
    log "4.未配置账户锁定策略,不安全"
    log "建议:"
    log "   执行 echo \"auth required pam_tally2.so onerr=fail deny=3 unlock_time=300 even_deny_root root_unlock_time=300\" >> /etc/pam.d/sshd 设置账户锁定，连续输错3次密码后，账户锁定5分钟"
    log "注:解锁账户执行 faillog -u <user> -r"
else
    log "4.已配置账户锁定,安全"
fi
COMMENT

# 1. 检查是否禁用密码登陆
echo -e "\033[33;1m 1.检查是否禁用密码登陆 \033[0m"
passwd_auth=`cat /etc/ssh/sshd_config | grep -v "^#" | grep "PasswordAuthentication" | awk "{print $2}"`
if [[ "$passwd_auth" =~ "no" ]]
then
    log  "1.已禁止密码登陆,安全"
else
    log " 1.密码登录未禁用,不安全"
    log  "建议:"
    log  "  修改/etc/ssh/sshd_config文件, 将PasswordAuthentication的值改为 no"
    log  "  重启ssh服务: systemctl restart sshd"
fi

# 2. 检查是否启用密钥登陆
echo -e "\033[33;1m 2.检查是否启用密钥登陆 \033[0m"
pubkey_auth=`cat /etc/ssh/sshd_config | grep -v "^#" | grep "PubkeyAuthentication" | awk "{print $2}"`
if [[ "$pubkey_auth" =~ "yes" ]]
then
    log  "2.已启用密钥登陆,安全"
else
    log " 2.未启用密钥登陆,不安全"
    log  "建议:"
    log  "  修改/etc/ssh/sshd_config文件, 将PubkeyAuthentication的值改为 yes"
    log  "  重启ssh服务: systemctl restart sshd"
fi
# 3. 检查是否禁用root账户本地登陆
echo -e "\033[33;1m 3.检查是否禁止root账户本地登陆 \033[0m"
local_root=`cat /etc/pam.d/login | grep 'auth required pam_succeed_if.so user != root quiet'`
if [[ "$local_root" == "" ]];
then
    log "3.未配置禁止root本地直接登陆,不安全"
    log "建议:"
    log "  请在/etc/pam.d/echoin文件最后添加一行auth required pam_succeed_if.so user != root quiet"
else
    log "3.已配禁止root账户本地直接登陆,安全"
fi
# 4. 检查是否存在develop预置账户
echo -e "\033[33;1m 4.检查是否添加预置账户 \033[0m"
user="develop"
user_exist=`cat /etc/passwd |cut -f 1 -d : |grep $user`
if [[ $user_exist != $user ]]
then
    log "4.未配置预置账户,不安全"
    log "建议:"
    log "  请联系开发创建预置账户"
else
    log "4.已配预置账户,安全"
fi

# 5.检查除root之外的账户UID为0
echo -e "\033[33;1m 5.检查除root之外的账户UID为0 \033[0m"
mesg=`awk -F: '($3==0) { print $1 }' /etc/passwd | grep -v root`
if [ "$mesg" != "" ]
then
    log "5.发现UID为0的账户,不安全"
    log "检查结果如下:"
    log "  $mesg"
    log "建议:"
    log "   上述账户UID为0,执行下面的操作进行修改"
    log "   usermod -u <new-uid> <user>"
    log "   groupmod -g <new-gid> <user>"
else
    log "5.未发现UID为0的账户,安全"
fi

# 6.检查环境变量包含父目录
echo -e "\033[33;1m 6.检查环境变量包含父目录 \033[0m"
parent=`echo $PATH | egrep '(^|:)(\.|:|$)'`
if [ "$parent" != "" ]
then
    log "6.环境变量中存在父目录,不安全"
    log "检查结果如下:"
    log "  $parent"
    log "建议:"
    log "   环境变量中不要带有父目录(..),请使用绝对路径或删除该环境变量"
else
    log "6.环境变量未包含父目录,安全"
fi

# 7.检查环境变量包含组权限为777的目录
echo -e "\033[33;1m 7.检查环境变量包含组权限为777的目录 \033[0m"
part=`echo $PATH | tr ':' ' '`
dir=`find $part -type d \( -perm -002 -o -perm -020 \) -ls`
if [ "$dir" != "" ]
then
    log "7.环境变量中包含组权限为777的目录"
    log "检查结果如下:"
    log "  $dir"
    log "建议:"
    log "   上述目录权限过高,请使用chmod 命令修改目录权限为744"
    log "   chmod -R 744 XX"
else
    log "7.未发现组权限为777的目录,安全"
fi

# 8.远程连接安全性
echo -e "\033[33;1m 8.远程连接安全性 \033[0m"
netrc=`find / -name .netrc`
rhosts=`find / -name .rhosts`
failed="0"
if [ "$netrc" == "" ]
then
    if [ "$rhosts" == "" ]
    then
        log "8.检查远程安全性通过,安全"
    else
        failed="1"
    fi
else
    failed="1"

fi
if [ "$failed" == "1" ]
then
    log "8.检查远程连接安全性未通过,不安全"
    log "检查结果如下:"
    log "  $netrc"
    log "  $rhosts"
    log "建议:"
    log "   请和管理员联系上述文件是否必要,如非必要,应当删除"
fi

# 9.检查umask配置
echo -e "\033[33;1m 9.检查umask配置 \033[0m"
bsetting=`cat /etc/profile /etc/bash.bashrc | grep -v "^#" | grep "umask"| awk '{print $2}'`
if [ "$bsetting" == "" ]
then
    log "9.umask 未配置,不安全"
    log "建议:"
    log "   执行 echo \"umask 022\" >> /etc/profile 增加umask配置"
else
    UMASK=`echo "$bsetting" | grep 022 | uniq`
    if [ "$UMASK" != "022" ]
    then
        log "9.umask 配置值不安全"
        log "检查结果如下:"
        log "  umask $UMASK"
        log "建议:"
        log "   修改/etc/profile /etc/bash.bashrc 文件"
        log "   设置的umask 命令为 \'umask 022\'"
    else
        log "9.umask 已配置,安全"
    fi
fi

# 10.检查重要文件和目录的权限
echo -e "\033[33;1m 10.检查重要文件和目录的权限 \033[0m"
content=
p=`ls -ld /etc`
content=`echo -e "$content\n$p"`
p=`ls -ld /etc/rc*.d`
content=`echo -e "$content\n$p"`
p=`ls -ld /tmp`
content=`echo -e "$content\n$p"`
p=`ls -l  /etc/inetd.conf`
content=`echo -e "$content\n$p"`
p=`ls -l  /etc/passwd `
content=`echo -e "$content\n$p"`
p=`ls -l  /etc/group `
content=`echo -e "$content\n$p"`
p=`ls -ld /etc/security`
content=`echo -e "$content\n$p"`
p=`ls -l  /etc/services`
content=`echo -e "$content\n$p"`
log "10. 检查重要文件和目录的权限"
log "检查结果如下:"
log "  $content"
log "建议:"
log "   请仔细检查以上文件和目录的权限,如果权限过高,请及时修改"


# 11.检查未授权的SUID/SGID文件
echo -e "\033[33;1m 11.检查未授权的SUID/SGID文件 \033[0m"
files=
for PART in `grep -v "^#" /etc/fstab | awk '($6 != "0") {print $2 }'`;
do
    FIND=`find $PART \( -perm -04000 -o -perm -02000 \) -type f -xdev -print`
    if [ "$FIND" != "" ]
    then
        files=`echo -e "$files\n$FIND"`
    fi
done
if [ "$files" != "" ]
then
    log "11.发现存在SUID和SGID的文件"
    log "检查结果如下:"
    log "  $files"
    log "建议:"
    log "   请检查上述文件是否可疑,如果可疑,请及时删除"
    log "   或修改权限为744并去除suid与sgid设置"
    log "   chmod  u-s  /XXX/XX"
    log "   chmod  g-s  /XXX/XX"
    log "   chmod  744  /XXX/XX"
else
    log "11.未发现存在SUID和SGID的文件,安全"
fi

# 12.检查任何人都有写权限的目录
echo -e "\033[33;1m 12.检查任何人都有写权限的目录 \033[0m"
files=
for PART in `awk '($3 == "ext2" || $3 == "ext3" || $3 == "ext4") {print $2 }' /etc/fstab`;do
    FIND=`find $PART -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print`
    if [ "$FIND" != "" ]
    then
        files=`echo -e "$files\n$FIND"`
    fi
done
if [ "$files" != "" ]
then
    log "12.发现任何人都有写权限的目录"
    log "检查结果如下:"
    log "  $files"
    log "建议:"
    log "   请及时修改权限为744"
    log "   chmod -R 744 XX.XX"
else
    log "12.未发现任何人都有写权限的目录,安全"
fi


# 13.检查任何人都有写权限的文件
echo -e "\033[33;1m 13.检查任何人都有写权限的文件 \033[0m"
files=
for PART in `grep -v "#" /etc/fstab | awk '($6 != "0") {print $2 }'`; do
    FIND=`find $PART -xdev -type f \( -perm -0002 -a ! -perm -1000 \) -print `
    if [ "$FIND" != "" ]
    then
        files=`echo -e "$files\n$FIND"`
    fi
done
if [ "$files" != "" ]
then
    log "13.发现任何人都有写权限的文件"
    log "检查结果如下:"
    log "  $files"
    log "建议:"
    log "   请修改权限为744"
    log "   chmod 744 XX.XX"
else
    log "13.未发现任何人都有写权限的文件,安全"
fi

# 14.检查没有属主的文件
echo -e "\033[33;1m 14.检查没有属主的文件 \033[0m"
files=
for PART in `grep -v "#" /etc/fstab | awk '($6 != "0") {print $2 }'`; do
    FIND=`find $PART -nouser -o -nogroup -print `
    if [ "$FIND" != "" ]
    then
        files=`echo -e "$files\n$FIND"`
    fi
done
if [ "$files" != "" ]
then
    log "14.发现没有属主的文件"
    log "检查结果如下:"
    log "  $files"
    log "建议:"
    log "   检查是否为可疑文件,可以文件请删除"
    log "   或修改可疑文件的权限 chmod 744 XX.XX"
else
    log "14.未发现没有属主的文件,安全"
fi

# 15.检查异常的隐藏文件
echo -e "\033[33;1m 15.检查异常的隐藏文件 \033[0m"
files=
FIND=`find / -name "..*" -print -xdev `
if [ "$FIND" != "" ]
then
    files=`echo -e "$files\n$FIND"`
fi
FIND=`find / -name "...*" -print -xdev | cat -v`
if [ "$FIND" != "" ]
then
    files=`echo -e "$files\n$FIND"`
fi
if [ "$files" != "" ]
then
    log "15.发现异常隐藏文件"
    log "检查结果如下:"
    log "  $files"
    log "建议:"
    log "   请检查上述文件是否可疑,如果可疑,请及时删除"
    log "   或修改可疑文件的权限 chmod 744 XX.XX"
else
    log "15.未发现可疑隐藏文件,安全"
fi

# 16.检查登录超时设置
echo -e "\033[33;1m 16.检查登录超时设置 \033[0m"
tmout=`cat /etc/profile | grep -v "^#" | grep TMOUT `
if [ "$tmout" == "" ]
then
    log "16.登录超时未配置,不安全"
    log "建议:"
    log "   执行 echo \"TMOUT=600\" >> /etc/profile 增加登录超时配置"
    log "   重新加载配置: source /etc/profile"
else
    log "16.登录超时已配置,安全"
fi

# 17. 检查ssh 和telnet运行状态
echo -e "\033[33;1m 17.检查ssh 和telnet运行状态 \033[0m"
ssh=`systemctl status sshd | grep running`
telnet=`systemctl status telnet | grep running`
if [ "$ssh" != "" ] && [ "$telnet" == "" ]
then
    log "17.telnet 未开启,安全"
else
    log "17.telnet 开启,不安全"
    log "检查结果如下:"
    if [ "$ssh" == "" ]
    then
        log "   ssh 未运行, 建议安装并开启ssh服务"
    fi
    if [ "$telnet" != "" ]
    then
        log "   telnet 运行中, 建议停止telnet服务"
    fi
fi


# 18. 远程登录限制
echo -e "\033[33;1m 18.远程登录限制 \033[0m"
permit=`cat /etc/ssh/sshd_config | grep -v "^#" | grep "PermitRootLogin" | awk "{print $2}"`
login_arg1=`cat /etc/ssh/sshd_config | grep -v "^#" | grep "UseDNS" | awk "{print $2}"`
login_arg2=`cat /etc/ssh/sshd_config | grep -v "^#" | grep "GSSAPIAuthentication" | awk "{print $2}"`

if [ "$permit" == "yes" ] || [ "$login_arg1" == "yes" ] || [ "$login_arg2" == "yes" ]
then
    log "18.允许root远程登录,不安全"
    log "检查结果如下:"
    log "  PermitRootLogin $permit"
    log "建议:"
    log "  修改/etc/ssh/sshd_config文件, 将PermitRootLogin　的值改为 no"
    log "  重启ssh服务: systemctl restart sshd"
elif [ "$login_arg1" == "yes" ] || [ "$login_arg2" == "yes" ]
then
    log "18.检查远程登录参数,不安全"
    log "检查结果如下:"
    log "  UseDNS $login_arg1"
    log "  GSSAPIAuthentication $login_arg2"
    log "建议:"
    log "  修改/etc/ssh/sshd_config文件"
    log "  将UseDNS的值改为 no"
    log "  将GSSAPIAuthentication的值为 no"
    log "  重启ssh服务: systemctl restart sshd"
else
    log "18.检查远程登录配置,安全"
fi


# 19. 检查运行的服务
echo -e "\033[33;1m 19.检查运行的服务 \033[0m"
chkconfig=`which chkconfig`
if [ "$chkconfig" == "" ]
then
    echo -n "19.未安装chkconfig,是否安装 (y/n) :"
    read i
    case $i in
        y|yes)
            apt-get install -y sysv-rc-conf
            cp /usr/sbin/sysv-rc-conf /usr/sbin/chkconfig
            echo "安装成功"
            ;;
        *)
            bcheck=0
            echo "未安装chkconfig,跳过此项检查"

            ;;
    esac
fi
level=`who -r | awk '{print $2}'`
process1=`chkconfig --list | grep "$level:开"`
process2=`chkconfig --list | grep "$level:on"`
if [ "$process1" != "" ]
then
    log "19.当前开启服务检查完成"
    log "检查结果如下:"
    log "  $process1"
    log "建议:"
    log "   请检查上述服务,尽量关闭不必要的服务"
    log "   注:使用命令\"chkconfig --level $level <服务名>\" 进行关闭"
elif [ "$process2" != "" ]
then
    log "19.当前开启服务检查完成"
    log "检查结果如下:"
    log "  $process2"
    log "建议:"
    log "   请检查上述服务,请确认是否需要关闭"
    log "   注:使用命令\"chkconfig --level $level <服务名>\" 进行关闭"
else
    log "19.无运行的服务,跳过"
fi

# 20. 检查core dump 状态
echo -e "\033[33;1m 20.检查core dump 状态 \033[0m"
SOFTFIND=`cat /etc/security/limits.conf | grep "^*.*soft.*core.*0"`
HARDFIND=`cat /etc/security/limits.conf | grep "^*.*hard.*core.*0"`
if [ "$SOFTFIND" != "" ] && [ "$HARDFIND" != "" ]
then
    log "20.core dump 检查正常,安全"
else
    log "20.core dump 检查不正常,不安全"
    log "建议:"
    log "   在/etc/security/limits.conf 文件中增加如下内容"
    log "   * soft core 0"
    log "   * hard core 0"
fi

# 21. 检查rsyslog状态
echo -e "\033[33;1m 21.检查rsyslog状态 \033[0m"
en=`systemctl is-enabled rsyslog`
conf=`cat /etc/rsyslog.conf | grep -v "^#" | grep "*.err;kern.debug;daemon.notice /var/adm/messages"`
if [ "$en" != "enabled" ]
then
    log "21.rsyslog未启动,不安全"
    log "建议:"
    log "   在/etc/rsyslog.conf中增加'*.err;kern.debug;daemon.notice /var/adm/messages'"
    log "   并执行以下命令:"
    log "   sudo mkdir /var/adm"
    log "   sudo touch /var/adm/messages"
    log "   sudo chmod 666 /var/adm/messages"
    log "   sudo systemctl restart rsyslog"
else
    if [ "$conf" == "" ];
    then
        log "21.检查rsyslog配置"
        log "建议:"
        log "   在/etc/rsyslog.conf中增加'*.err;kern.debug;daemon.notice /var/adm/messages'"
        log "   并执行以下命令:"
        log "   sudo mkdir /var/adm"
        log "   sudo touch /var/adm/messages"
        log "   sudo chmod 666 /var/adm/messages"
        log "   sudo systemctl restart rsyslog"
    else
        log "21.检查rsyslog配置,安全"
    fi
fi

# 22. 检查系统默认账户
echo -e "\033[33;1m 22.检查系统默认账户 \033[0m"
account=`awk -F: '($3 > 500) {print $1}' /etc/passwd`
uid=`awk -F: '($3 > 500) {print $3}' /etc/passwd`

if [ "$account" != "" ]
then
    log "22.存在非系统默认用户,不安全"
    log "检查结果如下:"
    log "  非默认账户:"$account
    log "建议:"
    log "  如非必要请删除该账号"
else
    log "22.没有非法账户存在,安全"
fi


# 23. 检查ftp服务状态
echo -e "\033[33;1m 23.检查ftp服务状态 \033[0m"
check_ftp=`ps aux |grep ftp`
if [ $check_ftp  ]
then
    log "23.ftp服务状态检测,不安全"
    log "建议:"
    log "    ftp服务正在运行,请关闭"
else
    log "23.ftp服务未开启,安全"
fi

# 24. 检查内核参数配置
echo -e "\033[33;1m 24.检查内核参数 \033[0m"
kernel_arg1=`cat /etc/sysctl.conf |grep "net.ipv4.conf.default.send_redirects=0" |wc -l`
kernel_arg2=`cat /etc/sysctl.conf |grep "net.ipv4.conf.default.accept_redirects=0" |wc -l`
if [ $kernel_arg1 == 0 ] || [ $kernel_arg2 == 0 ]
then
    log "24.检查内核参数配置,未屏蔽ip重定向,不安全"
    log "检查结果如下:"
    log "  net.ipv4.conf.default.send_redirects参数设置错误或不存在"
    log "  net.ipv4.conf.default.accept_redirects参数设置错误或不存在"
    log "建议:"
    log "    在/etc/sysctl.conf中添加:"
    log "    net.ipv4.conf.default.send_redirects=0"
    log "    net.ipv4.conf.default.accept_redirects=0"
    log "    重新加载配置: /sbin/sysctl -e -p /etc/sysctl.conf"
else
    log "24. 检查内核参数配置,安全"
fi


# 25. 检查icmp状态
echo "25.检查icmp配置,跳过"
#icmp_arg=`cat /etc/sysctl.conf |grep "net.ipv4.icmp_echo_ignore_all = 1" |wc -l`
#if [ $icmp_arg == 0 ]
#then
#    log "25.检查icmp配置,未忽略icmp请求,不安全"
#    log "检查结果如下:"
#    log "  net.ipv4.icmp_echo_ignore_all参数设置错误或不存在"
#    log "建议:"
#    log "    在/etc/sysctl.conf中添加:"
#    log "    net.ipv4.icmp_echo_ignore_all = 1"
#    log "    重新加载配置: /sbin/sysctl -e -p /etc/sysctl.conf"
#else
#    log "25.检查icmp参数配置,安全"
#fi

# 26. 检查定时任务
echo -e "\033[33;1m 26.检查定时任务\033[0m"
crontab_list=`cat /etc/passwd | cut -f 1 -d : |xargs -I {} crontab -l -u {}`
if [  "$crontab_list" != ""  ]
then
    log "26.定时任务检查结果如下:"
    log "  $crontab_list"
    log "请检查所有用户的定时任务是否非法"
    log "建议:"
    log "  非法定时任务请使用crontab -r user 删除该用户定时任务"
else
    log "26.没有定时任务,安全"
fi

# 27. 检查banner信息
echo -e "\033[33;1m 27.检查banner信息 \033[0m"
banner_info=`cat /etc/motd |grep "centos"`
if [ $banner_info != "" ]
then
    log "27.检查banner信息配置,泄漏了系统信息,不安全"
    log "检查结果如下:"
    log "  系统信息:"$banner_info
    log "建议:"
    log "  删除/etc/motd文件中关于系统的信息"
    log "  设置/etc/motd的权限为744"
    log "  chmod 744 XX.XX"
else
    log "27.检查banner信息配置,安全"
fi

# 28. 检查时间戳配置
echo -e "\033[33;1m 28.检查history时间戳是否配置 \033[0m"
history_value=`cat /etc/profile |grep "export HISTTIMEFORMAT"`
if [ $history_value == "" ]
then
    log "28.未设置history时间戳,不安全"
    log "建议:"
    log "  修改配置文件/etc/profile"
    log "  文件最后添加 : export HISTTIMEFORMAT='%Y-%m-%d %H:%M:%S  `whoami` '"
    log "  重新加载配置: source /etc/profile"
else
    log "28.已经设置history时间戳,安全"
fi



# 29. 检查系统默认ttl值
echo -e "\033[33;1m 29.检查系统默认的ttl值 \033[0m"
ttl_value=`sysctl -a |grep -i net.ipv4.ip_default_ttl | awk -F= '($2 == 64){print $2}'`
if [ $ttl_value != "" ]
then
    log "29.ttl的值为默认值64,不安全"
    log "建议:"
    log "  使用命令:vim /etc/sysctl.conf修改配置文件"
    log "  添加 : net.ipv4.ip_default_ttl = 128"
    log "  重新加载配置: /sbin/sysctl -e -p /etc/sysctl.conf"
else
    log "29.ttl值为非默认值,安全"
fi


# 30. 检查是否禁止ssh的cbc分组加密
echo -e "\033[33;1m 30.检查是否禁止ssh的cbc分组加密 \033[0m"
check_cbc=`cat /etc/ssh/sshd_config |grep "^Ciphers"`
if [ $check_cbc == "" ]
then
    log "30.未禁用cbc分组加密,不安全"
    log "建议:"
    log "  修改配置文件; /etc/ssh/sshd_config"
    log "  添加: Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,arcfour"
    log "  重启服务: systemctl restart sshd"
else
    log "30.已禁用cbc分组加密,安全"
fi


echo -e "\033[37;5m 检查完成, 请仔细阅读${logfile}文件\033[0m"
