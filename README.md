# Awesome-hacking-tools
好用的工具收集、大部分我都用过。部分会写上自己的感想，希望对你有帮助 / A collection of useful tools, most of which I have used. I hope it will be helpful to you



## 信息收集

> 分享一波自己觉得还不错的外网信息收集工具，在用工具收集完信息后，再结合手动的一些信息收集。提高效率的同时也更容易收获漏洞。 排名不分先后，感谢师傅的分享精神，网络安全有你们真不错!



### nemo_go

**开源 | 信息收集 | Golang | 资产管理**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220409234442857.png)

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220409234424091.png)



**简介:** Nemo是用来进行自动化信息收集的一个简单平台，通过集成常用的信息收集工具和技术，实现对内网及互联网资产信息的自动收集，提高隐患排查和渗透测试的工作效率，用Go语言完全重构了原Python版本

**点评:** 集成了IP资产、域名资产、指纹信息、API接口 、Poc验证与目录扫描、分布式任务。这一套操作还是界面可视化的，可以满足基础的对资产收集的需求了。还是开源项目，有不喜欢的地方可以自己二开，太香了。看了最近更新还是2022-3-8，个人开发者不容易，支持！

**地址:** https://github.com/hanc00l/nemo_go








### SiteScan

**开源 | 信息收集 | Python **

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220410150134627.png)

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220410150157188.png)

**简介:** 专注一站式解决渗透测试的信息收集任务。包括域名ip历史解析、nmap常见端口爆破、子域名信息收集、旁站信息收集、whois信息收集、网站架构分析、cms解析、备案号信息收集、CDN信息解析、是否存在waf检测、后台寻找以及生成检测结果html报告表等。

**点评:** python开发，自己写扫描器从里面参考点代码也是不错滴

**地址:** https://github.com/kracer127/SiteScan









### linglong

**开源 | 信息收集 | Golang | 资产管理**
![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/640.png)
![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/640-1.png)

**简介:** 一款资产巡航扫描系统。系统定位是通过masscan+nmap无限循环去发现新增资产，自动进行端口弱口令爆破/、指纹识别、XrayPoc扫描。主要功能包括: `资产探测`、`端口爆破`、`Poc扫描`、`指纹识别`、`定时任务`、`管理后台识别`、`报表展示`

**点评:** 我自己开发的，强行推荐一波

**地址:** https://github.com/awake1t/linglong





### scaninfo

**开源 | 信息收集 | Golang | 资产管理**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220410150844017.png)

**简介:** 开源、轻量、快速、跨平台 的红队内外网打点扫描器。快速的端口扫描和服务识别比masscan更快。包含fscan的绝大部份功能除了poc扫描和自定义字典

**地址:** https://github.com/redtoolskobe/scaninfo





### AppInfoScanner

**开源 | 移动端 | 信息收集 | Python **

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/AppInfoScanner.png)




**简介:** 一款适用于以HW行动/红队/渗透测试团队为场景的移动端(Android、iOS、WEB、H5、静态网站)信息收集扫描工具，可以帮助渗透测试工程师、攻击队成员、红队成员快速收集到移动端或者静态WEB站点中关键的资产信息并提供基本的信息输出,如：Title、Domain、CDN、指纹信息、状态信息等

**点评:** 用过，可以快速或者一些资产。

**地址:** https://github.com/kelvinBen/AppInfoScanner





### Glass

**开源 | 信息收集 | Python | 空间搜索引擎 **

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/Glass.png)


**简介:** Glass是一款针对资产列表的快速指纹识别工具，通过调用Fofa/ZoomEye/Shodan/360等api接口快速查询资产信息并识别重点资产的指纹，也可针对IP/IP段或资产列表进行快速的指纹识别。

**点评:** 直接集成了，用起来方便

**地址:** https://github.com/s7ckTeam/Glass


### Banli

**信息识别 | Golang | 高危扫描**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/image-20220410145544381.png)

**简介:** Banli是一款极其简单好用的高危资产识别和高危漏洞扫描工具。Banli要解决的问题是如何快速识别企业的高危资产，如何快速扫描企业的高危漏洞。包括Web资产、中间件资产、框架资产、安全设备等高危资产的识别，包括Web漏洞、命令执行漏洞、反序列化等高危漏洞的扫描. 作者：[0e0w](https://github.com/0e0w)

**地址:** https://github.com/Goqi/Banli




### ksubdomain

**开源 |  Golang | 域名收集**

![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/ksubdomain.png)
![image](https://github.com/awake1t/Awesome-hacking-tools/blob/master/img/ksubdomain1.png)

**简介:** ksubdomain是一款基于无状态的子域名爆破工具，类似无状态端口扫描，支持在Windows/Linux/Mac上进行快速的DNS爆破，拥有重发机制不用担心漏包。

**地址:** https://github.com/boy-hack/ksubdomain






