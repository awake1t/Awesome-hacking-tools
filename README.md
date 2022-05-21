
# Awesome-hacking-tools
好用的工具收集、大部分我都用过。部分会写上自己的感想，希望对你有帮助 / A collection of useful tools, most of which I have used. I hope it will be helpful to you

* [Awesome-hacking-tools](#awesome-hacking-tools)
   * [信息收集](#信息收集)
      * [nemo_go](#nemo_go)
      * [SiteScan](#sitescan)
      * [linglong](#linglong)
      * [scaninfo](#scaninfo)
      * [AppInfoScanner](#appinfoscanner)
      * [Glass](#glass)
      * [Banli](#banli)
      * [ksubdomain](#ksubdomain)
   * [泄露扫描](#泄露扫描)
      * [Packer Fuzzer](#packer-fuzzer)
      * [JSFinder](#jsfinder)
      * [HostCollision](#hostcollision)
      * [dirsearch](#dirsearch)
      * [gobuster](#gobuster)
      * [SecretFinder](#secretfinder)
   * [信息收集](#信息收集-1)
      * [OneForAll](#oneforall)
      * [Yasso](#yasso)
      * [ShuiZe_0x727](#shuize_0x727)
      * [Subfinder](#subfinder)
      * [GoScan](#goscan)
      * [SZhe_Scan](#szhe_scan)
      * [Raccoon](#raccoon)
   * [漏洞扫描](#漏洞扫描)
      * [xray](#xray)
      * [Nuclei](#nuclei)
      * [pocsuite3](#pocsuite3)
      * [Goby](#goby)
      * [fscan](#fscan)
      * [log4j-scan](#log4j-scan)
      * [weblogicScanner](#weblogicscanner)
   * [SRC批量工具](#src批量工具)
      * [ARL](#arl)
      * [Autoscanner](#autoscanner)
      * [SecurityServiceBox](#securityservicebox)
      * [HXnineTails](#hxninetails)
      * [domain_hunter_pro](#domain_hunter_pro)
      * [BBTz](#bbtz)


## 信息收集

> 分享一波自己觉得还不错的外网信息收集工具，在用工具收集完信息后，再结合手动的一些信息收集。提高效率的同时也更容易收获漏洞。 排名不分先后，感谢师傅的分享精神，网络安全有你们真不错!



### nemo_go

**开源 | 信息收集 | Golang | 资产管理**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/image-20220409234442857.png)

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/image-20220409234424091.png)



**简介:** Nemo是用来进行自动化信息收集的一个简单平台，通过集成常用的信息收集工具和技术，实现对内网及互联网资产信息的自动收集，提高隐患排查和渗透测试的工作效率，用Go语言完全重构了原Python版本

**点评:** 集成了IP资产、域名资产、指纹信息、API接口 、Poc验证与目录扫描、分布式任务。这一套操作还是界面可视化的，可以满足基础的对资产收集的需求了。还是开源项目，有不喜欢的地方可以自己二开，太香了。看了最近更新还是2022-3-8，个人开发者不容易，支持！

**地址:** https://github.com/hanc00l/nemo_go








### SiteScan

**开源 | 信息收集 | Python**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/image-20220410150134627.png)

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/image-20220410150157188.png)

**简介:** 专注一站式解决渗透测试的信息收集任务。包括域名ip历史解析、nmap常见端口爆破、子域名信息收集、旁站信息收集、whois信息收集、网站架构分析、cms解析、备案号信息收集、CDN信息解析、是否存在waf检测、后台寻找以及生成检测结果html报告表等。

**点评:** python开发，自己写扫描器从里面参考点代码也是不错滴

**地址:** https://github.com/kracer127/SiteScan









### linglong

**开源 | 信息收集 | Golang | 资产管理**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/640.png)
![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/640-1.png)

**简介:** 一款资产巡航扫描系统。系统定位是通过masscan+nmap无限循环去发现新增资产，自动进行端口弱口令爆破/、指纹识别、XrayPoc扫描。主要功能包括: `资产探测`、`端口爆破`、`Poc扫描`、`指纹识别`、`定时任务`、`管理后台识别`、`报表展示`

**点评:** 我自己开发的，强行推荐一波

**地址:** https://github.com/awake1t/linglong





### scaninfo

**开源 | 信息收集 | Golang | 资产管理**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/image-20220410150844017.png)

**简介:** 开源、轻量、快速、跨平台 的红队内外网打点扫描器。快速的端口扫描和服务识别比masscan更快。包含fscan的绝大部份功能除了poc扫描和自定义字典

**地址:** https://github.com/redtoolskobe/scaninfo





### AppInfoScanner

**开源 | 移动端 | 信息收集 | Python**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/AppInfoScanner.png)


**简介:** 一款适用于以HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、WEB、H5、静态网站)信息收集扫描工具，可以帮助渗透测试工程师、攻击队成员、红队成员快速收集到移动端或者静态WEB站点中关键的资产信息并提供基本的信息输出,如：Title、Domain、CDN、指纹信息、状态信息等

**点评:** 用过，可以快速或者一些资产。

**地址:** https://github.com/kelvinBen/AppInfoScanner





### Glass

**开源 | 信息收集 | Python | 空间搜索引擎**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/Glass.png)
![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/Glass.png)


**简介:** Glass是一款针对资产列表的快速指纹识别工具，通过调用Fofa/ZoomEye/Shodan/360等api接口快速查询资产信息并识别重点资产的指纹，也可针对IP/IP段或资产列表进行快速的指纹识别。

**点评:** 直接集成了，用起来方便

**地址:** https://github.com/s7ckTeam/Glass


### Banli

**信息识别 | Golang | 高危扫描**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/banlii.png)

**简介:** Banli是一款极其简单好用的高危资产识别和高危漏洞扫描工具。Banli要解决的问题是如何快速识别企业的高危资产，如何快速扫描企业的高危漏洞。包括Web资产、中间件资产、框架资产、安全设备等高危资产的识别，包括Web漏洞、命令执行漏洞、反序列化等高危漏洞的扫描. 作者：[0e0w](https://github.com/0e0w)

**地址:** https://github.com/Goqi/Banli




### ksubdomain

**开源 |  Golang | 域名收集**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/aa.png)

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/ksubdomain1.png)

**简介:** ksubdomain是一款基于无状态的子域名爆破工具，类似无状态端口扫描，支持在Windows/Linux/Mac上进行快速的DNS爆破，拥有重发机制不用担心漏包。

**地址:** https://github.com/boy-hack/ksubdomain







## 泄露扫描


### Packer Fuzzer

**开源 | 信息收集 | Python  | 1.3k Star**

![image-20220411195806686](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411195806686.png)

**简介:** **一款针对Webpack等前端打包工具所构造的网站**进行快速、高效安全检测的扫描工具。本工具支持自动模糊提取对应目标站点的API以及API对应的参数内容，并支持对：未授权访问、敏感信息泄露、CORS、SQL注入、水平越权、弱口令、任意文件上传七大漏洞进行模糊高效的快速检测。在扫描结束之后，本工具还支持自动生成扫描报告，您可以选择便于分析的HTML版本以及较为正规的doc、pdf、txt版本

**点评:** 如果你遇到VUE的站点，这个工具可能会给你带来惊喜

**地址:**https://github.com/rtcatc/Packer-Fuzzer




### JSFinder

**开源 | 信息收集 | Python | 1.5k Star**

![image-20220411185403267](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411185403267.png)



**简介:** JSFinder是一款用作快速在网站的js文件中提取URL，子域名的工具。提取URL的正则部分使用的是[LinkFinder](https://github.com/GerbenJavado/LinkFinder)

**点评:** 速度快，信息收集时候用起来还是很不错的！

**地址: **https://github.com/Threezh1/JSFinder





### HostCollision

**开源 | 信息收集 | Java  | 296 Star**

![image-20220411195030542](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411195030542.png)

![image-20220411195051733](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411195051733.png)

**简介:** 用于host碰撞而生的小工具,专门检测渗透中需要绑定hosts才能访问的主机或内部系统

**点评:** 在内网渗透中，有时候利用成功了。就离拿下不远了

**地址:** https://github.com/pmiaowu/HostCollision



### dirsearch

**开源 | 目录扫描 | Python  | 7.8k Star**

![image-20220411195456025](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411195456025.png)

**简介:**  网站路径扫描。使用字典破解网站目录和文件。而且支持递归破解

**点评:** 界面好看又快，作者还一直持续更新

**地址:https://github.com/maurosoria/dirsearch**



### gobuster

**开源 | 目录扫描  | Golang | 5.8k Star**

![image-20220411195418463](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411195418463.png)

**简介:** 跟dirsearch一样，可以爆破网站目录。功能还丰富点

- dir：传统的目录爆破模式
- dns：DNS子域名爆破模式
- vhost：虚拟主机爆破模式

**点评:** Golang版本，学习go的同学可以看看源码。能学习不少

**地址:**https://github.com/OJ/gobuster





### SecretFinder

**开源 | 信1息收集 | Python  | 7.8k Star**

![image-20220411200355799](https://github.com/awake1t/Awesome-hacking-tools/blob/main/img/02/image-20220411200355799.png)

**简介:** SecretFinder是一个基于LinkFinder的python脚本, 用来发现JavaScript中的敏感数据，如apikeys, accesstoken，未授权，jwt等

**点评:** 重点是规则，可以参考下他的规则

**地址:**https://github.com/m4ll0k/SecretFinder



> 欢迎各位大佬推荐你觉得很赞的项目，我的微信






## 信息收集


### OneForAll

**开源 | 信息收集 | Python**

**简介:**  OneForAll是一款功能强大的子域收集工具
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515419252-3c596bfa-faff-4177-8244-918657370dd0.png)

**点评:**  比较有名的信息收集工具，收集途径也比较全

**地址:**https://github.com/shmilylty/OneForAll





### Yasso

**开源 | 信息收集 | Golang**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515419084-e5d495e4-a57e-4bc1-b193-e4f2c8e4f186.png)

**简介:** 强大的内网渗透辅助工具集-让Yasso像风一样 支持rdp，ssh，redis，postgres，mongodb，mssql，mysql，winrm等服务爆破，快速的端口扫描，强大的web指纹识别，各种内置服务的一键利用（包括ssh完全交互式登陆，mssql提权，redis一键利用，mysql数据库查询，winrm横向利用，多种服务利用支持socks5代理执行

**点评:**  新工具，不错

**地址:** https://github.com/sairson/Yasso



### ShuiZe_0x727

**开源 | 信息收集 | Python**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515419118-6fdb1b79-f72a-4193-ac98-adf3b9bfd536.png)

**简介:** 协助红队人员快速的信息收集，测绘目标资产，寻找薄弱点。一条龙服务，只需要输入根域名即可全方位收集相关资产，并检测漏洞。也可以输入多个域名、C段IP等，具体案例见下文

**地址:** https://github.com/0x727/ShuiZe_0x727





### Subfinder

**开源 | 信息收集 | Python  | 域名收集**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515420406-b3ad34c1-3957-4f4b-a8dd-3f305764bf3b.png)

**简介:** SubFinder使用被动源，搜索引擎，Pastebins，Internet Archives等来查找子域。 

**点评:** 简单说，就是用API来收集域名。我参考过他的代码，很不错。

**地址:** https://github.com/projectdiscovery/subfinder





### GoScan

**开源 | 信息收集 | Golang | 资产管理**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515420406-b3ad34c1-3957-4f4b-a8dd-3f305764bf3b.png)
**简介:** 采用Golang语言编写的一款分布式综合资产管理系统，适合红队、SRC等使用

**点评:**  刚出来时候还不是开源，后来作者才开源的。为开源精神点赞！

**地址:**https://github.com/CTF-MissFeng/GoScan







### SZhe_Scan

**开源 | 信息收集 | Python  | 资产管理**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515420681-879d3038-d90e-424b-af8b-63a167caa2ac.png)

**简介:** 碎遮SZhe_Scan Web漏洞扫描器，基于python Flask框架，对输入的域名/IP进行全面的信息搜集，漏洞扫描，可自主添加POC

**地址:**https://github.com/Cl0udG0d/SZhe_Scan







### Raccoon

**开源 | 信息收集 | Python**

![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1650515421390-840cc648-f5bd-4816-bf33-c3844b39e477.png)

**简介:** 一款用于侦察和漏洞扫描的高性能攻击性安全工具。从获取DNS记录，TLS数据，WHOIS信息检索，WAF存在检测以及目录爆破，子域枚举等所有操作。每次扫描结果都将会输出保存到相应的文件中

**点评:**  看着python写的支持挺多功能，代码也模块化了。根据自己的需求，在他的基础上进行二次开发很方便

**地址:**https://github.com/evyatarmeged/Raccoon




## 漏洞扫描

### xray

**漏洞扫描 | 6.8k Star**

**简介:** 一款完善的安全评估工具，支持常见 web 安全问题扫描和自定义 poc
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1652354619392-dea8b406-ac45-4e5a-a1ab-13abe7b4d0cf.png)
**点评:** 可以用爬虫主动扫描，代理被动扫描。更新及时，官方不定期举办poc活动。配合登录态爬虫+被动扫描简直自动化神器，推荐！！

**地址:** [https://github.com/chaitin/xray](https://github.com/chaitin/xray)

### Nuclei

**开源 | 漏洞扫描 | Golang | 8.2k Star**

**简介:** Nuclei使用零误报的定制模板向目标发送请求，同时可以对大量主机进行快速扫描。Nuclei提供TCP、DNS、HTTP、FILE等各类协议的扫描，通过强大且灵活的模板，可以使用Nuclei模拟各种安全检查
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1652354619404-46782120-6dca-40a2-a0d4-a9137f89aea7.png)
**点评:** 跟xray类型，基于yaml的poc。但是这个是开源的，学习golang的朋友可以学习下代码。

**地址:** [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

### pocsuite3

**开源 | 漏洞扫描 | Python | 2.4k Star**

**简介:** pocsuite3是一个由Knownsec 404团队开发的开源远程漏洞测试框架
![](https://cdn.nlark.com/yuque/0/2022/jpeg/5363950/1652354619363-62344343-12e5-4bae-b031-2f50560c586f.jpeg)
**点评:** python开源，对目标进行批量主动扫描。知道创宇出品。挺不错的。

**地址:** [https://github.com/knownsec/pocsuite3](https://github.com/knownsec/pocsuite3)

### Goby
![](https://cdn.nlark.com/yuque/0/2022/jpeg/5363950/1652354619444-d0942ce3-9777-499f-9a65-a5abe8eec9db.jpeg)
**漏洞扫描**

**简介:** Goby是一款新的网络安全测试工具，由赵武Zwell（Pangolin、JSky、FOFA作者）打造，它能够针对一个目标企业梳理最全的攻击面信息，同时能进行高效、实战化漏洞扫描，并快速的从一个验证入口点，切换到横向

**点评:** 全平台好看的界面、可以开发插件、关注高危漏洞。批量扫网段真滴方便！

**地址:** [https://gobies.org/](https://gobies.org/)

### fscan

**开源 | 漏洞扫描 | Golang | 3.5k Star**

**简介:** 一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。 支持主机存活探测、端口扫描、常见服务的爆破、ms17010、redis批量写公钥、计划任务反弹shell、读取win网卡信息、web指纹识别、web漏洞扫描、netbios探测、域控识别等功能。
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1652354619374-b8444266-2496-498f-b30e-92bfbc5be33c.png)
**点评:** 内网渗透大宝剑

**地址:** [https://github.com/shadow1ng/fscan](https://github.com/shadow1ng/fscan)

### log4j-scan

**开源 | 漏洞扫描 | Python | 2.9k Star**

**简介:** 一个完全自动化、准确和广泛的扫描仪，用于查找log4j RCE CVE-2021-44228
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1652354619833-77fe53b7-6d68-4b5e-88fb-367d18438b6b.png)
**点评:** 核武器漏洞，说不定哪天还会用上

**地址:** [https://github.com/fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan)

### weblogicScanner

**开源 | 漏洞扫描 | Python | 1.3k Star**

**简介:** weblogic 漏洞扫描工具。目前包含对以下漏洞的检测能力：CVE-2014-4210、CVE-2016-0638、CVE-2016-3510、CVE-2017-3248、CVE-2017-3506、CVE-2017-10271、CVE-2018-2628、CVE-2018-2893、CVE-2018-2894、CVE-2018-3191、CVE-2018-3245、CVE-2018-3252、CVE-2019-2618、CVE-2019-2725、CVE-2019-2729、CVE-2019-2890、CVE-2020-2551、CVE-2020-14882、CVE-2020-14883
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1652354619911-f1734dc3-2167-4a2b-8ac9-72739d8d7570.png)
**点评:** 内网用这个批量试试，说不定会有惊喜

**地址:** [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner)




## SRC批量工具

  

> 本期是关于src挖洞中那些批量化的工。每个工具都有自己特色,适合在不同的场景下使用。祝你挖必洞！

### ARL

**开源 | 批量工具 | Python | 2.6k Star**
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110901488-6a980bb0-e2ff-4525-9d6f-8e06aca1910a.png)
**简介:** 快速侦察与目标关联的互联网资产，构建基础资产信息库。 协助甲方安全团队或者渗透测试人员有效侦察和检索资产，发现存在的薄弱点和攻击面。

**点评:** 界面方便、强大、好用

**地址:** [https://github.com/TophantTechnology/ARL](https://github.com/TophantTechnology/ARL)

### Autoscanner
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110901463-d095eba4-1755-4fdd-bb00-adcb022552b9.png)
**开源 | 批量工具 | Python | 438 Star**

**简介:** 输入域名>爆破子域名>扫描子域名端口>发现扫描web服务>集成报告的全流程全自动扫描器。集成oneforall、masscan、nmap、dirsearch、crawlergo、xray等工具，另支持cdn识别、网页截图、站点定位；动态识别域名并添加功能、工具超时中断等

**点评:** 开源集成工具,有需要的朋友直接二次开发

**地址:** [https://github.com/zongdeiqianxing/Autoscanner](https://github.com/zongdeiqianxing/Autoscanner)

### SecurityServiceBox

**开源 | 批量工具 | Python | 29 Star**
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110901466-2c0a0867-5f19-4c51-a92b-318a3c515135.png)
**简介:** 一个既可以满足安服仔日常渗透工作也可以批量刷洞的工具盒子。集合了常见的域名收集、目录扫描、ip扫描、指纹扫描、PoC验证等常用工具，方便安服仔快速展开渗透测试

**点评:** 最近1周内新更新,感觉日常快速验证可以试试

**地址:** [https://github.com/givemefivw/SecurityServiceBox](https://github.com/givemefivw/SecurityServiceBox)

### HXnineTails
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110901435-26be657b-82f3-43fa-b1ef-96945634edad.png)
**开源 | 批量工具 | Python | 233 Star**

**简介:** 平凡 暴力 强大 可自行扩展的缝合怪物。该项目中目前集成：crawlergo OneForAll subDomainsBrute Subfinder Sublist3r Xray JSfinder pppXray Server酱

**点评:** 文档写的也清晰，方便大家进行二次打开。给开源作者点赞

**地址:**

### domain_hunter_pro
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110901436-bacc3589-5f15-4dc4-8018-0a27908f0c8c.png)
**开源 | 批量工具 | Java | 1k Star**

**简介:** domain_hunter的高级版本，SRC挖洞、HW打点之必备！自动化资产收集；快速Title获取；外部工具联动；等等

**地址:** [https://github.com/bit4woo/domain_hunter_pro](https://github.com/bit4woo/domain_hunter_pro)


### BBTz
![](https://cdn.nlark.com/yuque/0/2022/png/5363950/1653110902027-a04be3b5-ab0a-40f4-82ac-2abf128b1e3a.png)
**开源 | 批量工具 | Python | 438 Star***

**简介:** BBT - Bug Bounty Tools

**点评:** 一些小脚本系列，JS中收集路径、域名。CSRF工具等等

**地址:** [https://github.com/m4ll0k/BBTz](https://github.com/m4ll0k/BBTz)


















