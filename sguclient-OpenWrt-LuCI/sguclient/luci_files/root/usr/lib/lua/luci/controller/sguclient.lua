module("luci.controller.sguclient", package.seeall)

function index()
        entry({"admin", "network", "sguclient"}, cbi("sguclient"), _("SGUClient LuCI"), 100)
        end