module("luci.controller.fusionX", package.seeall)

function index()
    entry({"admin", "fusionx"}, firstchild(), "FusionX", 60).dependent=false
    entry({"admin", "fusionx", "bonding"}, cbi("fusionX"), _("Bonding"), 1)
    entry({"admin", "fusionx", "statistics"}, call("action_statistics")).leaf = true
    entry({"admin", "fusionx", "set_lan1_static"}, call("action_set_lan1_static")).leaf = true
    entry({"admin", "fusionx", "info"}, cbi("fusionXinfo"), _("Info"), 2).leaf = true 
    entry({"admin", "fusionx", "changelog"}, cbi("fusionXchangelog"), _("Changelog"), 3).leaf = true 
end

function action_statistics()
    local sys = require "luci.sys"
    local json = require "luci.jsonc"
    local nixio = require "nixio"
    local interfaces = {"wwan0", "wwan1", "wwan2", "lan1", "lan2", "eth1", "eth2", "wan"}
    local data = {}
    local total_rx_speed = 0
    local total_tx_speed = 0
    
    local storage_file = "/tmp/fusionx_readings.json"
    
    local previous_readings = {}
    local f = io.open(storage_file, "r")
    if f then
        local content = f:read("*all")
        f:close()
        if content and #content > 0 then
            previous_readings = json.parse(content) or {}
        end
    end
    
    local current_time = os.time()
    
    for _, iface in ipairs(interfaces) do
        local status = sys.exec("ping -I " .. iface .. " -c 1 -W 1 8.8.8.8 > /dev/null 2>&1 && echo 'up' || echo 'down'")
        if status:match("up") then
            local rx = tonumber(sys.exec("cat /sys/class/net/" .. iface .. "/statistics/rx_bytes"))
            local tx = tonumber(sys.exec("cat /sys/class/net/" .. iface .. "/statistics/tx_bytes"))
            
            local rx_speed = 0
            local tx_speed = 0
            
            if previous_readings[iface] then
                local time_diff = current_time - previous_readings[iface].timestamp
                if time_diff > 0 then
                    rx_speed = ((rx - previous_readings[iface].rx) * 8) / (time_diff * 1024 * 1024)
                    tx_speed = ((tx - previous_readings[iface].tx) * 8) / (time_diff * 1024 * 1024)
                    
                    total_rx_speed = total_rx_speed + rx_speed
                    total_tx_speed = total_tx_speed + tx_speed
                end
            end
            
            -- Store current readings
            previous_readings[iface] = {
                rx = rx,
                tx = tx,
                timestamp = current_time
            }
            
            table.insert(data, {
                iface = iface,
                rx_speed = rx_speed,
                tx_speed = tx_speed
            })
        end
    end
    
    local f = io.open(storage_file, "w")
    if f then
        f:write(json.stringify(previous_readings))
        f:close()
    
        nixio.fs.chmod(storage_file, 644)
    end
    
    local response = {
        interfaces = data,
        total = {
            rx_speed = total_rx_speed,
            tx_speed = total_tx_speed
        }
    }
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(response)
end

function action_info()
    luci.http.prepare_content("text/plain")
    luci.http.write("This is the info page for FusionX.")
end
