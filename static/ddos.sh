#!/bin/bash
#4oct2020 by reaper
apt install dnsutils; apt-get install net-tools; apt-get install tcpdump; apt-get install dsniff -y; apt install grepcidr
clear
declare -A cor=( [0]="\033[33m" [1]="\033[1;34m" [2]="\033[1;35m" [3]="\033[1;32m" [4]="\033[1;31m" [5]="\033[1;33m" [6]="\E[44;1;37m" [7]="\E[41;1;37m" )
barra="\e[1;35m⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊⚊  \e[1;33m"
fun_bar () {
comando="$1"
 _=$(
$comando > /dev/null 2>&1
) & > /dev/null
pid=$!
while [[ -d /proc/$pid ]]; do
echo -ne " \033[1;33m["
   for((i=0; i<10; i++)); do
   echo -ne "\033[1;31m##"
   sleep 0.2
   done
echo -ne "\033[1;33m]"
sleep 1s
echo
tput cuu1 && tput dl1
done
echo -e " \033[1;33m[\033[1;31m####################\033[1;33m] - \033[1;32m100%\033[0m"
sleep 1s
}
ddosflateinstall () {
wget https://raw.githubusercontent.com/jgmdev/ddos-deflate/master/install.sh; chmod +x install.sh; ./install.sh
rm install.sh
clear
}
ddosuninstall () {
wget https://raw.githubusercontent.com/jgmdev/ddos-deflate/master/uninstall.sh; chmod +x uninstall.sh; ./uninstall.sh
rm unistall.sh
clear
}
addwthitelist () {
zonaipw=/etc/ddos/ignore.ip.list
read -p "Digite la IP: " IPWHITE
echo "$IPWHITE" >> $zonaipw
}
inicia-ddos () {
echo -e "$barra"
echo -e "\033[1;37mPROTECTOR DE ATAQUES DDOS \033[0m"
echo -e "\033[1;30mSi instalaste anteriormente el script
Primero Elige la opción 2 Unistall \033[0m"
echo -e "$barra"
while true; do
echo -e "${cor[3]} [1] › \033[1;33mInstalar DDOS Deflate"
echo -e "${cor[3]} [2] › \033[1;33mDesinstalar DDOS Deflate"
echo -e "${cor[3]} [3] › \033[1;33mAdd IP a lista Blanca"
echo -e "${cor[3]} [0] › \033[1;33mSALIR\n${barra}"
while [[ ${opx} != @(0|[1-3]) ]]; do
echo -ne "${cor[0]}Digite una Opcion: \033[1;37m" && read opx
tput cuu1 && tput dl1
done
case $opx in
	0)
	exit;;
	1)
	ddosflateinstall
    break;;
	2)
	ddosuninstall
    break;;
    3)
	addwthitelist
     break;;
esac
done
}
clear
inicia-ddos
