#!/bin/bash
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
SCPfrm="/etc/ger-frm" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="/etc/ger-inst" && [[ ! -d ${SCPinst} ]] && exit
dnschange () {
echo "nameserver $dnsp" > /etc/resolv.conf
/etc/init.d/ssrmu stop &>/dev/null
/etc/init.d/ssrmu start &>/dev/null
/etc/init.d/shadowsocks-r stop &>/dev/null
/etc/init.d/shadowsocks-r start &>/dev/null
msg -bar2
echo -e "${cor[4]}  DNS AGREGADOS CON EXITO"
} 
clear
msg -bar2
echo -e "\033[1;93m     ADICIONAR DNS PERSONALES "
msg -bar2
echo -e "\033[1;39m Si usas el DNS correcto podras tener soporte NETFLIX"
msg -bar2
echo -e "\033[1;39m En APPS como HTTP Inyector,KPN Rev,APKCUSTOM, etc."
echo -e "\033[1;39m Se deveran agregar en la aplicasion a usar estos DNS."
echo -e "\033[1;39m En APPS como SS,SSR,V2RAY no es necesario agregarlos."
msg -bar2
echo -e "\033[1;97m Ingrese su DNS a usar: \033[0;91m"; read -p "   "  dnsp
echo ""
msg -bar2
read -p " Estas seguro de continuar?  [ s | n ]: " dnschange   
[[ "$dnschange" = "s" || "$dnschange" = "S" ]] && dnschange
msg -bar2