require("luci.sys")

m = Map("sguclient", translate("SGUClient Log"), translate("Log file:/tmp/sguclient.log"))

s = m:section(TypedSection, "login", "")  --这里和上面的map一定要能对应到一个已经存在的配置文件的配置字段
s.addremove = false
s.anonymous = true
d = s:option(DummyValue, "d", translate("Notice for log"), translate("Log will only be saved if 'Save output log to file' is enabled."))
view_cfg = s:option(TextValue, "1", nil)
view_cfg.rows = 25
view_cfg.readonly = true

function view_cfg.cfgvalue()
    return nixio.fs.readfile("/tmp/sguclient.log") or "-No Log Found-"
end

return m
