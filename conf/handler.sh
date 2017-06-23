#!/bin/bash
if [ "$(id -ru)" = "0" ]; then
    SUDO=
else
    SUDO=sudo
fi
us_file="/etc/openvpn/users_settings.csv"
 # ##### Utility
 
 log() {
     local level
     level="$1"
     shift
     # Disabled:
     logger -t"ovpn-script[$$]" -pdaemon."$level" -- "$@"
 }
 
 # ##### Functions
 
 check_user() {
     if ! echo "$common_name" | grep ^[a-zA-Z][a-zA-Z0-9_-]*$; then
         log notice "Bad common name $common_name"
         return 1
     fi
 }
 
 # Write user specific OpenvPN configuration to stdout
 create_conf() {
    ip4ranges=$(cat /etc/openvpn/ip4ranges | tr " " "\n")
    reserve_ip "10.8.0.2-10.8.0.255" "${ip4ranges}"
    private_ip4=$(get_ip 2 )
    echo "ifconfig-push $private_ip4 $ifconfig_netmask"
    
    # Link to ipv4 if needed
    public_ip4=$(get_ip 3)
    if [ -n "$public_ip4" ]; then
        $SUDO iptables -t nat -A PREROUTING -d $public_ip4 -j DNAT --to-destination $private_ip4
        $SUDO iptables -t nat -A POSTROUTING -s ${private_ip4}/32 ! -d ${private_ip4}/32 -j SNAT --to-source $public_ip4
    else
        iface=$(ip r|awk '/default/ { print $5 }')
        $SUDO iptables -t nat -A POSTROUTING -s $private_ip4 -o "${iface}" -j MASQUERADE
    fi
}
 
 
get_first_ip () {
    echo $( netmask -x $(echo $1 | cut -f1 -d"-") | cut -f1 -d"/")
}
get_last_ip () {
    echo $( netmask -x $(echo $1 | cut -f1 -d"-") | cut -f1 -d"/")
}

# Put ip in www.xxx.yyy.zzz format
format_ip() {
    netmask $1 | cut -f1 -d"/" | sed -e 's/^[[:space:]]*//'
}

# Return the ip 
# $1 public|private
get_ip() {
    echo $(grep $common_name $us_file | awk -F"," "{print \$$1}")
    
}

get_next_ip() {

    for ip4range in $1
    do
        ip=$(($(get_first_ip $ip4range) + 0 ))
        last_ip=$(($(get_last_ip $ip4range) + 0))
        while [ "$ip" \< "$last_ip" ]
        do
            formated_ip=$(format_ip $ip)
            awk -F"," "{print \$$2}" $us_file | grep $formated_ip \
            || break 2
            ip=$(( $ip + 1 ))
        done
        formated_ip=$(format_ip $ip)
        awk -F"," "{print \$$2}" $us_file | grep $formated_ip \
        || break
    done
    if [ "$ip" \> "$last_ip" ]; then
        log notice "No more ip available"
        exit 1
    fi
    echo $formated_ip

}

# Return the static ip of the user, if needed define it
# $1 IPv4 ranges list ex: 10.8.0.0-10.8.0.255 10.8.1.0-10.8.1.255
# $2 Column number in user settings CSV
reserve_ip () {
    local registered_ip
    local private_ip
    local public_ip
    registered_ip=$(get_ip 2)
    if [ -z "$registered_ip" ]; then
        private_ip=$(get_next_ip $1 2)
        public_ip=$(get_next_ip $2 3 || true)
            
        echo "${common_name},${private_ip},${public_ip}" >> $us_file
    fi
}
 # ##### OpenVPN handlers
 
 client_connect() {
     conf="$1"
     check_user || exit 1
     create_conf > "$conf"
 }
 
 client_disconnect() {
     check_user || exit 1
 }
 
 # ##### Dispatch
 
 case "$script_type" in
     client-connect)    client_connect "$@" ;;
     client-disconnect) client_disconnect "$@" ;;
 esac
