module("luci.controller.sguclient", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/sguclient") then
        call("act_reset")
    end
    local page

    page = entry({ "admin", "network", "sguclient" }, firstchild(), _("SGUClient LuCI"), 80)

    entry({ "admin", "network", "sguclient", "client" }, cbi("sguclient/sguclient"), _("SGUClient LuCI"), 1)

    entry({ "admin", "network", "sguclient", "Log" }, cbi("sguclient/log"), _("Log"), 2).leaf = true
end

function act_reset()
    --Not impl yet
end