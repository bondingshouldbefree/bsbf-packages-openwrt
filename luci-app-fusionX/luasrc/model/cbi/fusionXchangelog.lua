local fs = require "nixio.fs"

m = SimpleForm("info", translate("FusionX Changelog"))
m.reset = false
m.submit = false

s = m:section(SimpleSection, nil, translate("<h2>V1.0.0</h2>"))

-- Text
local text = s:option(DummyValue, "_text")
text.rawhtml = true
text.value = [[
    <div class="cbi-value-field">
        - XMS integration, auto negotation with xms server.<br><br>
        - New UI.<br><br>
        - Notification section (communication with server for updates).<br><br>
        - Bonding section, to turn the bond off/on.<br><br>
        - Client name default to mac address or input manually<br><br>
        - Xms inputs for device name, xms profile name<br><br>
        - Failover optimised<br><br>
        - Vodacom fix (work in progress)<br><br>
        - VOIP, video call optimisation<br><br>
        - File download over browser persist after interface down<br><br>
        - Info/Help section (new menu item)<br><br>
        - Social links in info section<br><br>
    </div>
]]

a = m:section(SimpleSection, nil, translate("<h2>V1.1.0</h2>"))

-- Text
local text = a:option(DummyValue, "_text")
text.rawhtml = true
text.value = [[
    <div class="cbi-value-field">
        - Start/stop bond optimization.<br><br>
        - Remote update section, to update the router from the web interface.<br><br>
        - Remove submit button and keep everything on save and apply.<br><br>
        - Add changelog page.<br><br>
    </div>
]]


return m