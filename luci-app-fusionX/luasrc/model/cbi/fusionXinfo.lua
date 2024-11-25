local fs = require "nixio.fs"

m = SimpleForm("info", translate("FusionX Info"))
m.reset = false
m.submit = false

s = m:section(SimpleSection, nil, translate("<h2>Starting the Bond</h2>"))

-- Text
local text = s:option(DummyValue, "_text")
text.rawhtml = true
text.value = [[
    <div class="cbi-value-field">
        By default your router will come with the bond enabled, to turn it off you can uncheck the 'enable bonding' checkbox and click 'save and apply' at the bottom of the page.<br><br>
        This will turn the bond off and it will persist across reboots, to turn it back on just check the checkbox and click 'save and apply' again. You can verify that your bond is off/on via the IP displayed next to the 'Bond Server'. If it's 0.0.0.0, then you are not bonded.
    </div>
]]

a = m:section(SimpleSection, nil, translate("<h2>Notifications</h2>"))

-- Text
local texta = a:option(DummyValue, "_text")
texta.rawhtml = true
texta.value = [[
    <div class="cbi-value-field">
        Every now and then, you will received an 'Update Available' notification. This is because FusionX is under active development and updates are released frequently.<br><br>
        Simply click the upgrade button next to 'Upgrade Firmware' to update FusionX.
    </div>
]]

b = m:section(SimpleSection, nil, translate("<h2>Troubleshooting</h2>"))

-- Text
local textb = b:option(DummyValue, "_text")
textb.rawhtml = true
textb.value = [[
    <div class="cbi-value-field">
        If you are experiencing issues with FusionX, such as connectivity issues, please check the following:<br><br>
        1. Ensure your router is on the latest firmware by checking your notifications section<br>
        2. Ensure your APNS are set correctly<br>
        3. Try running /etc/init.d/fusionX restart in the command line<br>
        4. Ensure your individual links have stable internet<br>
        5. Reboot the router<br>
        6. If all else fails, contact our support via support@xpedite-tech.com<br>
    </div>
]]

c = m:section(SimpleSection, nil, translate("<h2>Licensing</h2>"))

-- Text
local textc = c:option(DummyValue, "_text")
textc.rawhtml = true
textc.value = [[
    <div class="cbi-value-field">
        FusionX has a free license available to all clients, simply type 'Free' into the license key field and click 'Submit'.<br><br>
        The Free license permits up to 50mbps of uncapped aggregate speed.<br><br>
        To obtain higher speeds, please visit our site and select a higher tier license.<br><br>
        If you have a license key, you can enter it into the license key field and click 'Submit'.
    </div>
]]

e = m:section(SimpleSection, nil, translate("<h2>License Activation</h2>"))

-- Text
local texte = e:option(DummyValue, "_text")
texte.rawhtml = true
texte.value = [[
    <div class="cbi-value-field">
        To enable a new License, enter your key in the Activation Key on FusionX bonding page then restart the bond by deactivating and activating again:<br><br>
    </div>
]]

d = m:section(SimpleSection, nil, translate("<h2>Socials</h2>"))

-- Text
local textd = d:option(DummyValue, "_text")
textd.rawhtml = true
textd.value = [[
    <div class="cbi-value-field">
        Because FusionX falls under the BondingShouldBeFree initiative which promises open source bonding, we have a number of socials and github pages where you can find more information and even have a go at improving it yourself!:<br><br>
        <a href="https://discord.gg/EweqwRq2aq">Our discord</a><br>
        <a href="https://github.com/bondingshouldbefree/openwrtmptcp/tree/mptcp-bpi-r4">Our github</a><br>
    </div>
]]
return m
