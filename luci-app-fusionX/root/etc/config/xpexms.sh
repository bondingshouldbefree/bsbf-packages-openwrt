#!/bin/ash

# Initialize the flag
lua_executed=false
hascnf=false
hasca=false
hasclicrt=false
hasclikey=false
cliname=$(uci get fusionX.settings.clientcomp)
SERVER_IP="10.8.0.1"
devicename=$(uci get fusionX.settings.xmsname)
mac=$(cat /sys/class/net/eth0/address)
vpn_zone_exists=0
zone_count=$(uci show firewall | grep '\.name=' | wc -l)

outputstring=""
mcc=""
mnc=""
lac=""
cell_id=""
lon=""
lat=""
port_string=""
isregistered=false
# create a uci config file for xmsconfig
parse_port() {
    local port="$1"
    local output="$2"
    
    # Extract Link detected status
    local link_status=$(echo "$output" | awk '/Link detected:/ {print $3}')
    
    # Append to port_string
    if [ -n "$link_status" ]; then
        port_string="${port_string}${port},${link_status}."
    fi
}
parse_interface() {
    local interface="$1"
    local output="$2"
    local rx_bytes=$(echo "$output" | awk '/RX bytes:/ {print $2}' | cut -d':' -f2)
    local tx_bytes=$(echo "$output" | awk '/TX bytes:/ {print $6}' | cut -d':' -f2)
    local inet_addr=$(echo "$output" | awk '/inet addr:/ {print $2}' | cut -d':' -f2)

    # Check if RX or TX bytes are non-zero
    if [ "$rx_bytes" != "0" ] || [ "$tx_bytes" != "0" ]; then
        outputstring=$outputstring"$interface,$rx_bytes,$tx_bytes,$inet_addr.%%"
    fi
}

extract_gps_coordinates() {
    # Call the gpsd position command and capture the output
    output=$(ubus call gpsd position 2>/dev/null)
    
    # Check if the output contains "longitude" and "latitude"
    if echo "$output" | grep -q '"longitude":' && echo "$output" | grep -q '"latitude":'; then
        # Extract longitude and latitude using sed or awk
        lon=$(echo "$output" | grep -o '"longitude":[^,]*' | sed 's/.*://')
        lat=$(echo "$output" | grep -o '"latitude":[^,]*' | sed 's/.*://')
    else
        # If not found, set lon and lat to empty or some default value
        lon=""
        lat=""
    fi
}

fetch_tower() {
  serving_cell_info=$(ubus call gsm.modem0 get_serving_cell)
  net_reg_info=$(ubus call gsm.modem0 get_net_reg_stat)

  # Extract values from serving cell info
  mcc=$(echo "$serving_cell_info" | ash -c 'JSON="$1"; echo "$JSON" | jsonfilter -e @.list[0].mcc' -- "$serving_cell_info")
  mnc=$(echo "$serving_cell_info" | ash -c 'JSON="$1"; echo "$JSON" | jsonfilter -e @.list[0].mnc' -- "$serving_cell_info")

  # Extract values from network registration info
  lac=$(echo "$net_reg_info" | ash -c 'JSON="$1"; echo "$JSON" | jsonfilter -e @.lac' -- "$net_reg_info")
  cell_id=$(echo "$net_reg_info" | ash -c 'JSON="$1"; echo "$JSON" | jsonfilter -e @.ci' -- "$net_reg_info")
}

PID_FILE="/etc/config/reach_instance.pid"

if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE")
  if [ -n "$OLD_PID" ] && [ -e /proc/$OLD_PID ]; then
    echo "Stopping instance: $OLD_PID"
    kill $OLD_PID
    sleep 2
  fi
  rm -f "$PID_FILE"
fi

echo $$ > "$PID_FILE"

dropbearconfig="
  config dropbear
	option PasswordAuth 'on'
	option Port         '22'
"

echo "$dropbearconfig" > /etc/config/dropbear

initconfig="
# Put your custom commands here that should be executed once
# the system init finished. By default this file does nothing.

sh /etc/config/xpereachstart.sh >/dev/null 2>&1 &
sh /etc/config/DataCollectMain.sh >/dev/null 2>&1 & 
echo 'scripts started'

exit 0
"
echo "$initconfig" > /etc/rc.local

if test -f "/etc/config/DataCollectMain.sh"
then
:
else
touch "/etc/config/DataCollectMain.sh"
fi

for idx in $(seq 0 $((zone_count - 1))); do
  if [ "$(uci get firewall.@zone[$idx].name 2>/dev/null)" = "XPEvpnXMS" ]; then
    vpn_zone_exists=1
    break
  fi
done

if [ "$vpn_zone_exists" -eq 1 ]; then
  echo "VPN zone exists."
else
  echo "VPN zone does not exist."
  uci add firewall rule
  uci set firewall.@rule[-1].target='ACCEPT'
  uci set firewall.@rule[-1].src='XPEvpnXMS'
  uci set firewall.@rule[-1].proto='tcp'
  uci set firewall.@rule[-1].dest_port='22'
  uci set firewall.@rule[-1].name='Allow-SSH-vpn'

  uci add firewall zone
  uci set firewall.@zone[-1].name='XPEvpnXMS'
  uci add_list firewall.@zone[-1].network='XPEvpnXMS'
  uci set firewall.@zone[-1].input='ACCEPT'
  uci set firewall.@zone[-1].output='ACCEPT'
  uci set firewall.@zone[-1].forward='REJECT'

  uci set network.XPEvpnXMS=interface
  uci set network.XPEvpnXMS.ifname='tun0'
  uci set network.XPEvpnXMS.proto='none'
  
  /etc/init.d/firewall restart
  /etc/init.d/network restart 
  sleep 10
fi

# Command to start the OpenVPN service, adjust if necessary
VPN_SERVICE_START="openvpn --daemon --config /etc/openvpn/client.ovpn"

# Number of pings to attempt
PING_COUNT=2

# Perform the ping test
serverstate="none"
while true; do
    # Main script
    echo "Interfaces with non-zero traffic:"
    echo ""
    port_string=""
    portinterfaces="lan1 lan2 lan3 wan wwan0 wwan1 wwan2 wwan3 wlan0 wlan1"
    for pinterface in $portinterfaces; do
        ethtool_output=$(ethtool "$pinterface" 2>/dev/null)
        parse_port "$pinterface" "$ethtool_output"
    done
    ifconfig_output=$(ifconfig)
    interfaces=$(echo "$ifconfig_output" | awk '/^[a-zA-Z0-9]+/ {print $1}')
    outputstring=""
    for interface in $interfaces; do
        interface_output=$(echo "$ifconfig_output" | awk -v RS= '/^'"$interface"' /')
        parse_interface "$interface" "$interface_output"
    done
    # echo $outputstring
    extract_gps_coordinates
    fetch_tower
    nowtx=$(cat /sys/class/net/eth0/statistics/tx_bytes)
    nowrx=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    
    google_ping=$(ping -c 1 google.com | awk -F'/' 'END{print $5}')
    response=$(curl -X POST -s -w '%{http_code}' -H "Content-Type: application/json" -d "{\"mac\": \"$mac\",\"cliname\": \"$cliname\",\"devicename\": \"$devicename\",\"outstring\": \"$outputstring\",\"portstring\": \"$port_string\",\"lat\": \"$lat\",\"lon\": \"$lon\",\"mcc\": \"$mcc\",\"mnc\": \"$mnc\",\"lac\": \"$lac\",\"cellid\": \"$cell_id\",\"tx\": \"$nowtx\", \"rx\": \"$nowrx\", \"ping\": \"$google_ping\"}" http://102.132.169.58:7788/XMScheckin)
    
    # echo $response
    
    if [ "$response" = "Created201" ] && [ "$lua_executed" = false ]; then
        # Fetch and process the message
        curl -X POST -d "title=$cliname $devicename" http://102.132.169.58:7788/getCA -o /etc/openvpn/ca.crt
        curl -X POST -d "title=$cliname $devicename" http://102.132.169.58:7788/getClientCRT -o /etc/openvpn/client.crt
        curl -X POST -d "title=$cliname $devicename" http://102.132.169.58:7788/getClientKEY -o /etc/openvpn/client.key
        curl -X POST -d "title=$cliname $devicename" http://102.132.169.58:7788/getCF -o /etc/openvpn/client.ovpn
        # Set the flag to true to prevent multiple executions
        echo "vpn starting"
        openvpn --daemon --config /etc/openvpn/client.ovpn
        echo "vpn started"
        lua_executed=true
    elif [ "$response" != "Created201" ]; then
        if pgrep openvpn >/dev/null; then
            killall openvpn
        fi
        lua_executed=false
    fi
    sleep 2
done