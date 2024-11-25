#!/bin/ash

wwans="wwan1 wwan2 wwan3"

checkinterface() {
    echo "Checking modem $1"
    local modem_id="$1"
    local modem_info=$(mmcli -m $modem_id)
    # echo "$modem_info"
    if echo "$modem_info" | grep -q "failed"; then
        echo "Modem $modem_id is failed, resetting"
        mmcli -m $modem_id -r
        sleep 20
        for wwan in $wwans; do
            ifup $wwan
        done
    fi
    if echo "$modem_info" | grep -q "disabled"; then
        echo "Modem $modem_id is disabled, bringing up"
        for wwan in $wwans; do
            ifup $wwan
        done
    fi
}

modems=$(mmcli -L)
modem_ids=$(echo "$modems" | sed -n 's/.*Modem\/\([0-9]*\).*/\1/p')

# Start all checks in background
for modem_id in $modem_ids; do
    checkinterface $modem_id &
done

# Wait for all background processes to complete
wait

echo "All modem checks completed"