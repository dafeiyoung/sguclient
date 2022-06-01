require("luci.sys")

m = Map("sguclient", translate("SGUClient Log"), translate("Log file:")
        .. [[&nbsp;]]
        .. translate("/var/log/sguclient.log")
)

s = m:section(TypedSection, "login", "")  --这里和上面的map一定要能对应到一个已经存在的配置文件的配置字段
s.addremove = false
s.anonymous = true
view_cfg = s:option(TextValue, "1", nil)
view_cfg.rows = 25
view_cfg.readonly = true

function view_cfg.cfgvalue()
    return nixio.fs.readfile("/var/log/sguclient.log") or "-No Log Found-"
end

return m
