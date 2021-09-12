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

extranetName = s:option(Value, "extranetUsername", translate("extranet Username"),translate("Fill in your extranet username"))
extranetPass = s:option(Value, "extranetPassword", translate("extranet Password"),translate("Fill in your extranet password"))
extranetPass.password = true

isptype=s:option(ListValue,"isptype",translate("ISP Type"),translate("Chose your ISP Type"))
isptype:value("D",translate("CTCC(DX)"))
isptype:value("Y",translate("CMCC(YD)")) 

ifname = s:option(ListValue, "ifname", translate("AuthInterface"),translate("Chose your authentication interface"))

wanip = s:option(Value, "wanip", translate("Wan IP Address"),translate("Authentication interface IPv4 address(must be the same as which filled in 'Network-Interfaces')"))
wanip.datatype="ip4addr"

for k, v in ipairs(luci.sys.net.devices()) do
	if v ~= "lo" then
		ifname:value(v)
	end
end

local apply = luci.http.formvalue("cbi.apply")
if apply then
	io.popen("/etc/init.d/sguclient restart")
end

return m
