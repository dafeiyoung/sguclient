# 韶关学院校园网第三方拨号器

当年年少不懂事，东拼西凑弄的一个小东西，现在毕业了，留给有需要的师弟师妹吧。Have fun anyway！

## 关于
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient是一个纯C系语言编写的**韶关学院**学生宿舍区第三方网络认证拨号器。现在有Ubuntu和OpenWrt二进制文件可用。当然了，得益于C系语言良好的可移植性，你可以获得SGUClient的源代码然后轻松移植到你需要的平台上（Feel free to make changes）。
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient内置2套拨号协议，所以在全校、全网应该都可以正常使用。准确来说，兼容电信和移动网络，兼容南区、北区和西区网络，兼容Drcom拨号器和新旧小蝴蝶拨号器。但黄田坝校区和紫藤苑未经实地测试。
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;现在SGUClient也有了LuCI图形化配置页面，所以在OpenWrt路由器上运行SGUClient或许是一个不错的选择。

## 严肃警告
- 仅可用于学习目的

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient及其有关资料仅可供韶关学院师生用于学习计算机网络知识、学习计算机编程知识的用途，其他任何用途均为不正常使用。由于不正常使用所导致的一切直接或间接后果及法律责任均由使用者自行承担，SGUClient作者不承担任何责任。
- 禁止用于商业用途

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;特别指出禁止任何个人或团体将SGUClient或其有关资料用于商业目的。由此造成的后果与法律责任均与开发者、公众号持有者以及QQ群友无关！
- 从未授权任何商业、推广活动

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**SGUClient是免费、开源软件，用户无需为其支付任何费用！**

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient的开发者从未授权任何形式的商业活动、推广活动，也不提供任何付费服务。一切与SGUClient有关的商业活动、推广活动（包括但不限于`收费代刷路由器`、`收费上门推广安装WiFi`等）均为不正常使用的行为。SGUClient开发者对这些不正常使用的行为不知情、不支持、不鼓励，也不会承担任何责任。你在参与这些不正常使用的行为中付出的代价（例如`跑路`、`金钱损失`、`隐私信息被盗`、`封号`等）均与SGUClient开发者无关！
- 不鼓励用于分享网络

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient的出发点是给韶关学院师生提供一些可供学习研究的编程资料，因此不鼓励利用SGUClient或其有关资料进行分享网络的行为（包括但不限于`开WiFi`、`多人合用一条宽带`等）。与他人分享网络可能是违规行为！
- 抵制商业用途

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;窃取他人免费开源的劳动成果用于赚钱是不道德的行为；付费让别人代刷路由器是助纣为虐的行为，更是对自己的隐私安全不负责任的行为。

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;`收费代刷路由器`、`收费上门推广安装WiFi`等高调作死行为只会加速得罪有关利益方，让别人尽快封杀SGUClient。哪天没得研究了就是你们这些人亲手造成的；

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;同时，这些代刷的路由器中会不会偷偷安插了木马软件用于`盗号`、`监控网络隐私`、`窃取机密资料`等违法犯罪用途，谁也说不准。为了你自己的隐私安全，请勿轻信`收费代刷路由器`、`收费上门推广安装WiFi`等服务。

## 快速上手
* [Ubuntu使用SGUClient](https://github.com/dafeiyoung/sguclient/wiki/Ubuntu%E4%BD%BF%E7%94%A8SGUClient)<br>
* [OpenWrt(路由器)使用SGUClient](https://github.com/dafeiyoung/sguclient/wiki/OpenWrt(%E8%B7%AF%E7%94%B1%E5%99%A8)%E4%BD%BF%E7%94%A8SGUClient)<br>

## 编译
* [Ubuntu编译SGUClient](https://github.com/dafeiyoung/sguclient/wiki/Ubuntu%E7%BC%96%E8%AF%91SGUClient)<br>
* [交叉编译SGUClient For OpenWrt](https://github.com/dafeiyoung/sguclient/wiki/%E4%BA%A4%E5%8F%89%E7%BC%96%E8%AF%91SGUClient-For-OpenWrt)

## 故障排除
* [故障排除](https://github.com/dafeiyoung/sguclient/wiki/%E6%95%85%E9%9A%9C%E6%8E%92%E9%99%A4)

## 版权声明
SGUClient是很久很久之前弄的一个东西了，编写过程中借(chao)鉴(xi)了很多开源项目的源代码。主要有：<br>
* drcom协议部分使用了[fsn_server](https://github.com/YSunLIN/fsn_server)的源代码
* 程序框架使用了ZTE-Client的源代码
* LuCI部分使用了[njit-client](http://www.cnblogs.com/mayswind/p/3468124.html)的LuCI部分源代码
<br>_历史久远，如果有遗留，请联系我。_
<br>感谢以上作者的辛勤付出。侵删。
<br>
欢迎star，欢迎fork，欢迎pull request，但禁止任何个人或团体将SGUClient用于商业目的，由此造成的后果与法律责任均与开发者、公众号持有者以及QQ群友无关！

## 再说几句
a. 历时很多很多年改来改去的一个东西，当年shit一样的代码风格，所以请勿在饭前饭后阅读源代码。
<br>
b. 欢迎加入`QQ群638138948`讨论。韶关学院师生进群请备注“学院-年级-昵称”例如“信工-14-二狗子”，非韶关学院师生进入请备注学校（这只是为了方便统计，希望理解）。
