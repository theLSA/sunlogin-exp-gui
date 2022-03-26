# sunlogin-exp-gui：java GUI版向日葵RCE漏洞利用工具



## 0x00 概述

202202，网上爆出远程管理工具向日葵的RCE漏洞，利用check接口和cookie中的cid值即可远程命令执行。


## 0x01 影响范围

向日葵个人版for Windows <= 11.0.0.33

向日葵简约版 for windows <= V1.0.1.43315（2021.12）

/

11.1.1

10.3.0.27372

11.0.0.33162


## 0x02 功能介绍

主界面：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-01.png)


### 端口扫描

目标格式：单ip/c段/ip段/单域名。

端口格式：单端口/端口范围。

端口扫描方式：socket / nmap（socket方式可自定义线程数、连接时间、是否先icmp检测主机存活 。/ nmap模式须要有nmap工具并填写路径。）。

stop：暂停扫描。

export：导出扫描有可利用端口的结果（socket模式或nmap模式）。

clear：清空输出界面。

单ip扫描+powershell执行命令：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-02.png)

c段扫描+导出结果：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-03.png)

nmap模式扫描：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-04.png)

### 漏洞检测

三个输入框分别为：

目标地址

exp

verify_string

9种exp可选：

String[] expList = new String[] {"powershell","cmd0","cmd1","cmd2","getVerifyString","getFastcode","getAddress","getLoginType","customEXP"};

自定义连接时间（默认10s）

cmd0执行命令：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-05.png)

获取verify_string：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-06.png)

cmd2执行命令：

![](https://github.com/theLSA/sunlogin-exp-gui/raw/master/demo/sunlogin-exp-gui-07.png)


## 0x03 开发细节

环境配置:jdk1.8+swing+eclipse+windowbuilder1.9.7

使用的第三方库：


https://github.com/seancfoley/IPAddress

https://github.com/google/gson

https://github.com/kevinsawicki/http-request


### 端口扫描


发现大概率开启49000以上的端口，可以先扫描49000-50000，再扫描50000-60000。

多线程：
ExecutorService newFixedThreadPool + Future

Socket检测开放端口，若发现开放端口，则调用GetSunloginInfo类的get_sunlogin_vuln_api_port()获取web指纹检查是否是可利用的sunlogin端口，扫描一个端口开放立刻获取指纹，符合就结束，避免多余的端口扫描和指纹获取。

多线程利用isReachable检测主机存活，提高效率。

nmap端口扫描：直接调用外部nmap程序，对输出结果进行处理。

nmapProcess = Runtime.getRuntime().exec(nmapDir + nmapCommand + " " + nmapTarget);

对扫描结果是开放的端口执行web指纹检查判断是否是sunlogin可利用端口。


### 漏洞检测


GetSunloginInfo类还有get_fastcode()等获取sunlogin信息的exp。

rce_by_check_api()利用check这个api接口执行命令，先判断verify_string是否为空，是则先调用get_verify_string()获取，再进行rce。


## 0x04 TODO

1.美化GUI。

2.增加从文件导入目标。

3.增加EXP。

4.实现暂停-启动功能。

5.人性化提示，输入处理。

6.提高扫描效率。

7.解决中文乱码。


## 0x05 反馈

[issues](https://github.com/theLSA/sunlogin-exp-gui/issues)

