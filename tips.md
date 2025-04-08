### OSCP+ 
```
初始扫描
ZenMap 扫描TCP （UDP）
扫描结果是否提示了有趣的信息？
是否有不常见的端口？
高端口检查了吗？
常见的端口是否可以默认密码登录？
扫描UDP了吗？SNMP检查了吗？
sudo $(which autorecon) <IP>
未知端口nc了吗？敲version或help试过吗？

Web扫描
检查autorecon的扫描结果
若没有，运行feroxbuster -u <IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
是否有有趣的文件？
robots.txt
CHANGELOG.txt
README.md
Sitemap.xml
.git目录
是否有有趣的路径？（/api，/hostname）
是否需要修改hosts文件？
是否能获取到Web应用的版本号？版本是否有RCE？
如果是常见程序，是否能找到扫描工具？
Wordpress - WPscan, droopescan
Drupal - droopescan
是否能找到登录页面？
是否试过默认密码？admin:admin, admin:password, hostname:hostname, root:root
可能存在SQL注入（能否拿到表信息？能否运行xp_cmdshell？）
是否有LFI？RFI？可以上传文件吗？
反向shell无法回弹？有防火墙吗？试试80端口？

Windows拿到低权限后
运行systeminfo
运行whoami /priv
检查C盘根目录是否有有趣的文件？
扫描家目录dir /s /a /t:w . 
仔细检查并且没有遗漏吗？（尤其是Desktop, Documents）
C:\Users下有几个用户？
运行winPEASx64.exe
若无有效信息，运行Seatbelt.exe, PrivescCheck.ps1, Snaffler.exe, SharpUp.exe
有定时任务吗？
有有趣的服务吗？有带空格但是没有引号的路径吗？
有AlwaysInstallElevated吗？
环境变量有有趣的信息吗?
PowerShell历史记录检查了吗？
检查已经安装的程序（PuTTY等可能可以发现密码，检查注册表）
若有Keepass，则搜索数据库
若有XAMPP，则搜索配置文件
若有OpenSSH, PuTTY则检查密码
拿到的所有密码在所有服务上测试了吗？
Sticky Note里有有趣的信息吗？
若需要UAC绕过，考虑MSF + Meterpreter payload

Linux拿到低权限后
运行uname -a
运行sudo -l （www-data也要sudo -l）
运行find / -perm -u=s -type f 2>/dev/null
扫描家目录find . -printf "%p\\t%TY-%Tm-%Td %TH:%TM\\n"
仔细检查并且没有遗漏吗？
/home下有几个用户？
运行linpeas.sh
是否有有趣的进程？
检查是否有127.0.0.1的端口
检查是否有任何黄色高亮？
是否提示了任何密码？
Linux版本是否易受攻击？uname -r/-a（DirtyCow, DirtyPipe?）
是否有定时任务？
有有趣的服务吗？
用户是否是某个有趣的组的成员？
有没有可写的路径？有没有可修改的文件？环境变量能改吗？
有备份文件吗？
.bash_history检查了吗？
pspy64能否获取密码？
拿到的所有密码在所有服务上测试了吗？
系统上有gcc吗？（可能需要编译exp）
linux下，测一下gcc是否存在，如果存在 有可能提权路径是 让你编译一个基于uname -a的提权exp
gcc的判断建议手动看，可能被重命名
```
