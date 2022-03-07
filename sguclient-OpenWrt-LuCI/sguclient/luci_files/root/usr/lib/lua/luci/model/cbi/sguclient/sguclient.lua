--[[
LuCI - Lua Configuration Interface

Copyright 2010 Jo-Philipp Wich <xm@subsignal.org>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0
]]--

require("luci.sys")

m = Map("sguclient", translate("SGUClient LuCI"), translate("ShaoGuan University 3rd Party Network Authentication Client.<br/><b><font color=\"red\">QQ Group: 638138948</font></b>"))

s = m:section(TypedSection, "login", "")
s.addremove = false
s.anonymous = true

enable = s:option(Flag, "enable", translate("Enable"),translate("Main control of SGUClient"))
enable = s:option(Flag, "autoreconnect", translate("Auto Reconnect"),translate("Reconnect if client went off-line(Generally NOT checked)"))
enable = s:option(Flag, "noheartbeat", translate("No 1x Heart Beat"),translate("No 802.1x heart beat and cancel alarm(Generally NOT checked)"))

name = s:option(Value, "username", translate("1x Username"),translate("Fill in your 802.1x username"))
pass = s:option(Value, "password", translate("1x Password"),translate("Fill in your 802.1x password"))
pass.password = true

isptype=s:option(ListValue,"isptype",translate("ISP Type"),translate("Chose your ISP Type"))
isptype:value("D",translate("CTCC(DX)"))
isptype:value("Y",translate("CMCC(YD)"))

ifname = s:option(ListValue, "ifname", translate("AuthInterface"),translate("Chose your authentication interface"))
for k, v in pairs(luci.sys.net.devices()) do
	if v ~= "lo" then
		ifname:value(v)
	end
end



function ifname.validate(self, value) --未保存时无法直接传递选择的网卡名 通过文件中转
	luci.sys.exec("touch /tmp/sguclient.ifname")
	luci.sys.exec("echo %s >/tmp/sguclient.ifname"%value)
	return value
end


b=s:option(Button,"GetIpFromIf",translate("Get Ip Address from interface"))

wanip = s:option(Value, "wanip", translate("Wan IP Address"),translate("Authentication interface IPv4 address(must be the same as which filled in 'Network-Interfaces')"))
wanip.datatype="ip4addr"


function b.write(self,section,value)
	local ifip
	local readdd=luci.sys.exec(" tail -1 /tmp/sguclient.ifname  ")
	if(readdd~="" and #readdd <=16) then --后面那个是防止找不到文件
		readdd = (string.gsub(readdd, "'" , ""))
		readdd = (string.gsub(readdd, "\n", ""))
		readdd = (string.gsub(readdd, "\r", ""))

		for _, v in pairs(nixio.getifaddrs()) do
			if v.family == "inet" and v.name == readdd then
				ifip=v.addr
			end
		end
	end

	function wanip.cfgvalue()  -- 从mentohust看到的奇妙用法
		return ifip or ""
	end
end



local apply = luci.http.formvalue("cbi.apply")
if apply then
	nixio.fs.remove("/tmp/sguclient.ifname")
	io.popen("/etc/init.d/sguclient restart")
end

return m
