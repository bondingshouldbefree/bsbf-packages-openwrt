local sys = require "luci.sys"
local http = require "luci.http"
local uci = require "luci.model.uci".cursor()
local versionthis = 'V1.0.0'
local m = Map("fusionX", translate("Bonding"))

local function file_exists(name)
    local f = io.open(name, "r")
    if f then
        f:close()
        return true
    else
        return false
    end
end

local current_ip = uci:get("fusionX", "settings", "public_ip")

if(current_ip == "0.0.0.0") then
    sys.exec("/etc/init.d/fusionX disable")
end

current_ip = uci:get("fusionX", "settings", "public_ip")

m.description = translate("Bond Server: ") .. current_ip

local mac_address = "none"

local current_version = uci:get("fusionX", "settings", "version")

local curl_command = string.format("curl -s -m 2 -X POST -d 'versionthis=%s' http://102.132.169.58:4270/fusionxversion", current_version)
local server_response = sys.exec(curl_command):gsub("\n", ""):gsub("^%s*(.-)%s*$", "%1")
server_response = server_response:gsub('^"(.-)"$', '%1')

local message_text = "up to date"
local show_upgrade_button = false

sys.exec("echo 'Processed server response: " .. server_response .. "' >> /tmp/fusionX.log")

if server_response == "upgrade" then
    message_text = "new version available"
    show_upgrade_button = true
    sys.exec("echo 'Comparison successful' >> /tmp/fusionX.log")
else
    sys.exec("echo 'Comparison failed: [" .. server_response .. "]' >> /tmp/fusionX.log")
end

local message_section = m:section(NamedSection, "settings", "fusionX", translate("Notifications"))
local message = message_section:option(DummyValue, "message", translate("Message"))
message.value = message_text

if show_upgrade_button then
    local upgrade_btn = message_section:option(Button, "upgrade", translate("Upgrade firmware"))
    upgrade_btn.inputtitle = translate("Upgrade")
    upgrade_btn.inputstyle = "apply"
    
    function upgrade_btn.write(self, section)
        local template = message:formvalue(section)
        local download_command = "curl -o /tmp/fusionXUpgrade.itb http://102.132.169.58:4270/getcurrentversion"
        local result = sys.exec(download_command)
        if file_exists("/tmp/fusionXUpgrade.itb") then
            sys.exec("sysupgrade /tmp/fusionXUpgrade.itb")
            luci.http.redirect(luci.dispatcher.build_url("admin", "fusionx", "bonding") .. "?message=Upgrade%20successful")
        else
            luci.http.redirect(luci.dispatcher.build_url("admin", "fusionx", "bonding") .. "?message=Upgrade%20failed")
        end
    end
end

local p = m:section(NamedSection, "settings", "fusionX", translate("Settings"))


local po = p:option(Flag, "bond_enabled", translate("Enable Bonding"))

local xm = p:option(Flag, "isxms", translate("XMS"))

local clientcomp_value = uci:get("fusionX", "settings", "clientcomp")
local clientcomp = p:option(Value, "clientcomp", translate("Client Company"))
if clientcomp_value == "none" then
    clientcomp.default = "Please set company"
else
    clientcomp.default = clientcomp_value
end

local clientxms_value = uci:get("fusionX", "settings", "xmsname")
local clientxms = p:option(Value, "xmsname", translate("Device Name"))
if clientxms_value == "none" then
    clientxms.default = "Please set Device Name"
else
    clientxms.default = clientxms_value
end

local client_name = p:option(Value, "clientname", translate("Client Name"))

local activation_key = p:option(Value, "activation_key", translate("Activation Key"))

local activate_btn = p:option(Button, "_activate_btn", translate("Activate"))
activate_btn.inputtitle = translate("Redetect Sims")
activate_btn.inputstyle = "apply"

function activate_btn.write(self, section)
    local key = activation_key:formvalue(section)
    sys.exec("sh /etc/config/Simredetect.sh &")
    luci.http.redirect(luci.dispatcher.build_url("admin", "fusionx", "bonding"))
end

local interfaces = {"wwan0", "wwan1", "wwan2", "lan1", "lan2", "wan", "eth1", "eth2"}

local function get_rx_tx(iface)
    local rx = sys.exec("cat /sys/class/net/" .. iface .. "/statistics/rx_bytes")
    local tx = sys.exec("cat /sys/class/net/" .. iface .. "/statistics/tx_bytes")
    
    return rx, tx
end

local active_section = m:section(SimpleSection, nil, translate("Active Interfaces"))

local table = active_section:option(DummyValue, "_table", "")
table.rawhtml = true

local html = [[
<style>
    .chart-container {
        width: 800px; 
        height: 300px;
        margin-top: 20px;
    }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns"></script>
<div id="charts-container"></div>
<script type="text/javascript">
    const chartColors = {
        total: {
            rx: ['rgba(75, 192, 192, 0.3)', 'rgba(75, 192, 192, 1)'],
            tx: ['rgba(255, 99, 132, 0.3)', 'rgba(255, 99, 132, 1)']
        },
        interfaces: [
            ['rgba(255, 159, 64, 0.3)', 'rgba(255, 159, 64, 1)'],   // orange
            ['rgba(153, 102, 255, 0.3)', 'rgba(153, 102, 255, 1)'], // purple
            ['rgba(54, 162, 235, 0.3)', 'rgba(54, 162, 235, 1)'],   // blue
            ['rgba(255, 206, 86, 0.3)', 'rgba(255, 206, 86, 1)'],   // yellow
            ['rgba(75, 192, 192, 0.3)', 'rgba(75, 192, 192, 1)'],   // green
            ['rgba(255, 99, 132, 0.3)', 'rgba(255, 99, 132, 1)'],   // red
            ['rgba(128, 0, 128, 0.3)', 'rgba(128, 0, 128, 1)'],     // deep purple
            ['rgba(0, 128, 128, 0.3)', 'rgba(0, 128, 128, 1)'],     // teal
            ['rgba(255, 140, 0, 0.3)', 'rgba(255, 140, 0, 1)'],     // dark orange
            ['rgba(106, 90, 205, 0.3)', 'rgba(106, 90, 205, 1)'],   // slate blue
            ['rgba(60, 179, 113, 0.3)', 'rgba(60, 179, 113, 1)'],   // medium sea green
            ['rgba(219, 112, 147, 0.3)', 'rgba(219, 112, 147, 1)'], // pale violet red
            ['rgba(70, 130, 180, 0.3)', 'rgba(70, 130, 180, 1)'],   // steel blue
            ['rgba(205, 92, 92, 0.3)', 'rgba(205, 92, 92, 1)'],     // indian red
            ['rgba(147, 112, 219, 0.3)', 'rgba(147, 112, 219, 1)'], // medium purple
            ['rgba(32, 178, 170, 0.3)', 'rgba(32, 178, 170, 1)'],   // light sea green
        ]
    };
    
    const previousData = {
        total: { rx: 0, tx: 0, timestamp: new Date() },
        interfaces: {}
    };
    
    const ctx = document.createElement('canvas');
    ctx.className = 'chart-container';
    document.getElementById('charts-container').appendChild(ctx);

    let chart;
    
    function initializeChart() {
        chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Total Download (Mbps)',
                        borderColor: chartColors.total.rx[1],
                        backgroundColor: chartColors.total.rx[0],
                        data: [],
                        fill: true,
                        tension: 0.2
                    },
                    {
                        label: 'Total Upload (Mbps)',
                        borderColor: chartColors.total.tx[1],
                        backgroundColor: chartColors.total.tx[0],
                        data: [],
                        fill: true,
                        tension: 0.2
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'second'
                        }
                    },
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        });
    }
    
    function updateStatistics() {
        fetch('/cgi-bin/luci/admin/fusionx/statistics')
            .then(response => response.json())
            .then(data => {
            const now = new Date();
            const currentInterfaces = new Set(data.interfaces.map(item => item.iface));
            
            // First update: Initialize datasets if they don't exist
            if (chart.data.datasets.length <= 2) { // Only total upload/download exist
                data.interfaces.forEach((item, index) => {
                    const colorIndex = index % chartColors.interfaces.length;
                    
                    // Add download dataset
                    chart.data.datasets.push({
                        label: `${item.iface} Download`,
                        borderColor: chartColors.interfaces[colorIndex][1],
                        backgroundColor: chartColors.interfaces[colorIndex][0],
                        data: new Array(chart.data.labels.length).fill(0), // Fill with zeros to match existing labels
                        fill: false,
                        tension: 0.2,
                        pointRadius: 0,
                        borderWidth: 1,
                        interfaceId: item.iface,
                        isRx: true
                    });
                    
                    // Add upload dataset
                    chart.data.datasets.push({
                        label: `${item.iface} Upload`,
                        borderColor: chartColors.interfaces[colorIndex][1],
                        backgroundColor: chartColors.interfaces[colorIndex][0],
                        data: new Array(chart.data.labels.length).fill(0), // Fill with zeros to match existing labels
                        fill: false,
                        tension: 0.2,
                        pointRadius: 0,
                        borderWidth: 1,
                        interfaceId: item.iface,
                        isRx: false,
                        borderDash: [5, 5]
                    });
                });
            }

            // Update data points
            chart.data.datasets.forEach(dataset => {
                if (dataset.interfaceId) {
                    const item = data.interfaces.find(d => d.iface === dataset.interfaceId);
                    if (item) {
                        dataset.data.push(dataset.isRx ? item.rx_speed : item.tx_speed);
                    } else {
                        dataset.data.push(0);
                    }
                }
            });

            // Update total speeds
            chart.data.labels.push(now);
            chart.data.datasets[0].data.push(data.total.rx_speed);
            chart.data.datasets[1].data.push(data.total.tx_speed);

            // Maintain chart history
            if (chart.data.labels.length > 30) {
                chart.data.labels.shift();
                    chart.data.datasets.forEach(dataset => dataset.data.shift());
                }

                chart.update();
            })
            .catch(error => console.error('Error fetching statistics:', error));
    }

    initializeChart();
    setInterval(updateStatistics, 1500);
    updateStatistics();
</script>
]]

table.value = html

local apply = luci.http.formvalue("cbi.apply")
if apply then
    luci.sys.call("/etc/init.d/fusionX reload")
end

return m
