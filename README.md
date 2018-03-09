# 韶关学院校园网第三方拨号器

当年年少不懂事，东拼西凑弄的一个小东西，现在毕业了，留给有需要的师弟师妹吧。Have fun anyway！

## 关于
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient是一个纯C系语言编写的**韶关学院**学生宿舍区第三方网络认证拨号器。现在有Ubuntu和OpenWrt二进制文件可用。当然了，得益于C系语言良好的可移植性，你可以获得SGUClient的源代码然后轻松移植到你需要的平台上（Feel free to make changes）。
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SGUClient内置2套拨号协议，所以在全校、全网应该都可以正常使用。准确来说，兼容电信和移动网络，兼容南区、北区和西区网络，兼容Drcom拨号器和新旧小蝴蝶拨号器。但黄田坝校区和紫藤苑未经实地测试。
<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;现在SGUClient也有了LuCI图形化配置页面，所以在OpenWrt路由器上使用SGUClient或许是一个不错的选择。

## Change Log
release0.18(2017.11.25)
<br>1. 加入LuCI配置页。
<br>2. 同步移动网拨号协议到最新版移动小蝴蝶拨号器协议（2017.9更新的新版本小蝴蝶协议）。
<br>3. 同步电信网协议到最新电信协议（~~离校前一晚赶工改的，没有时间做大量测试，如果不稳定请联系我~~&nbsp;&nbsp;更新：开学这几天已经有五六十人安装了，他们反映说还是很稳的）。

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
欢迎star，欢迎fork，欢迎pull request，但禁止任何个人或机构将SGUClient用于商业目的，由此造成的后果与法律责任均与开发者、公众号持有者以及QQ群友无关！

## 再说几句
a. 历时很多很多年改来改去的一个东西，当年shit一样的代码风格，所以请勿在饭前饭后阅读源代码。
<br>
b. 欢迎加入`QQ群638138948`讨论。韶关学院师生进群请备注“学院-年级-昵称”例如“信工-14-二狗子”，非韶关学院师生进入请备注学校（这只是为了方便统计，希望理解）。
