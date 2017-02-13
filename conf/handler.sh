#!/bin/sh
 if [ "$(id -ru)" = "0" ]; then
     SUDO=
 else
     SUDO=sudo
 fi
 
 # ##### Utility
 
 log() {
     local level
     level="$1"
     shift
     # Disabled:
     # logger -t"ovpn-script[$$]" -pdaemon."$level" -- "$@"
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
    ip4=$(grep $common_name /etc/openvpn/ip4_attribution.csv | awk -F"," '{print $2}')
    if [ -z $ip4 ] ; then
        ip4=$(find_available_ip ${ip4ranges})
        echo "${common_name},${ip4}" >> /etc/openvpn/ip4_attribution.csv
    fi
    gateway=$(netmask -s $(echo $ip4ranges | cut -f1 -d" ") | cut -f1 -d"/")
    IP4=$(netmask $ip4 | cut -f1 -d"/")
     if ! [ -z "$IP4" ]; then
         echo "ifconfig-push $IP4 $gateway"
     fi
     if ! [ -z "$IP6" ]; then
         echo "ifconfig-ipv6-push $IP6/64 $ifconfig_ipv6_local"
     fi
     if ! [ -z "$PREFIX" ]; then
         # Route the IPv6 delegated prefix:
         echo "iroute-ipv6 $PREFIX"
         # Set the OPENVPN_DELEGATED_IPV6_PREFIX in the client:
         echo "push \"setenv-safe DELEGATED_IPV6_PREFIX $PREFIX\""
     fi
 }
 
 add_route() {
     $SUDO ip route replace "$@"
 }
 
 # Add the routes for the user in the kernel
 add_routes() {
     if ! [ -z "$IP4" ]; then
         log info "IPv4 $IP4 for $common_name"
         add_route $IP4/32 dev $dev protocol static
     fi
     if ! [ -z "$IP6" ]; then
         log info "IPv6 $IP6 for $common_name"
         add_route $IP6/128 dev $dev protocol static
     fi
     if ! [ -z "$PREFIX" ]; then
         log info "IPv6 delegated prefix $PREFIX for $common_name"
         add_route $PREFIX via $IP6 dev $dev protocol static
     fi
 }
 
 remove_routes() {
     if ! [ -z "$IP4" ]; then
         $SUDO ip route del $IP4/32 dev $dev protocol static
     fi
     if ! [ -z "$IP6" ]; then
         $SUDO ip route del $IP6/128 dev $dev protocol static
     fi
     if ! [ -z "$PREFIX" ]; then
         $SUDO ip route del $PREFIX via $IP6 dev $dev protocol static
     fi
 }
 
 set_routes() {
     if ! add_routes; then
         remove_routes
         return 1
     fi
 }
 
get_first_ip () {
    
    echo $( netmask -x $(echo $1 | cut -f1 -d"-") | cut -f1 -d"/")
}
get_last_ip () {
    echo $( netmask -x $(echo $1 | cut -f2 -d"-") | cut -f1 -d"/")
}
find_available_ip () {
    i=0
    for ip4range in $1
    do
        ip4range=$(netmask -r $ip4range | cut -f4 -d" ")
        ip=$(($(get_first_ip $ip4range) + 0 ))
        last_ip=$(($(get_last_ip $ip4range) + 0))
        if [ $i -eq 0 ]; then
            gateway=$ip
            ip=$(( $ip + 1 ))
        fi
        while [ "$ip" \< "$last_ip" ]
        do
            awk -F"," '{print $2}' /etc/openvpn/ip4_attribution.csv | grep $ip \
            || break 2
            ip=$(( $ip + 1 ))
        done
	awk -F"," '{print $2}' /etc/openvpn/ip4_attribution.csv | grep $ip \
	|| break
        i=$(( $i + 1 ))
    done
    if [ "$ip" \> "$last_ip" ]; then
        log notice "No more ip available"
        exit 1
    fi
    echo $ip

}
 # ##### OpenVPN handlers
 
 client_connect() {
     conf="$1"
     check_user || exit 1
     create_conf > "$conf"
     #set_routes
 }
 
 client_disconnect() {
     check_user || exit 1
     #remove_routes
 }
 
 # ##### Dispatch
 
 case "$script_type" in
     client-connect)    client_connect "$@" ;;
     client-disconnect) client_disconnect "$@" ;;
 esac
