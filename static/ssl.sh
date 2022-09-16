#!/bin/bash

sshports=`netstat -tunlp | grep sshd | grep 0.0.0.0: | awk '{print substr($4,9); }' > /tmp/ssh.txt && echo | cat /tmp/ssh.txt | tr '\n' ' ' > /etc/newadm/sshports.txt && cat /etc/newadm/sshports.txt`;

mportas () {
unset portas
portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" |grep -v "COMMAND" | grep "LISTEN")
while read port; do
var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
[[ "$(echo -e $portas|grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
done <<< "$portas_var"
i=1
echo -e "$portas"
}

colores
lor1='\033[1;31m';lor2='\033[1;32m';lor3='\033[1;33m';lor4='\033[1;34m';lor5='\033[1;35m';lor6='\033[1;36m';lor7='\033[1;37m'

if [ $(id -u) -eq 0 ];then
clear
else
echo -e "Ejecutar Script Como Usuario${lor2}root${lor7}"
exit
fi 

fun_bar () {
          comando[0]="$1"
          comando[1]="$2"
          (
          [[ -e $HOME/fim ]] && rm $HOME/fim
          ${comando[0]} > /dev/null 2>&1
          ${comando[1]} > /dev/null 2>&1
          touch $HOME/fim
          ) > /dev/null 2>&1 &
          tput civis
		  echo -e "${lor7}---------------------------------------------------${lor7}"
          echo -ne "${lor7}    AGUARDE..${lor1}["
          while true; do
          for((i=0; i<18; i++)); do
          echo -ne "${lor5}#"
          sleep 0.2s
          done
         [[ -e $HOME/fim ]] && rm $HOME/fim && break
         echo -e "${col5}"
         sleep 1s
         tput cuu1
         tput dl1
         echo -ne "${lor7}    AGUARDE..${lor1}["
         done
         echo -e "${lor1}]${lor7} -${lor7} FINALIZADO ${lor7}"
         tput cnorm
		 echo -e "${lor7}---------------------------------------------------${lor7}"
 }
        
fun_bar2 () {
comando[0]="$1"
comando[1]="$2"
 (
[[ -e $HOME/fim ]] && rm $HOME/fim
${comando[0]} -y > /dev/null 2>&1
${comando[1]} -y > /dev/null 2>&1
touch $HOME/fim
 ) > /dev/null 2>&1 &
echo -ne "\033[1;33m ["
while true; do
   for((i=0; i<18; i++)); do
   echo -ne "\033[1;31m☵"
   sleep 0.1s
   done
   [[ -e $HOME/fim ]] && rm $HOME/fim && break
   echo -e "\033[1;33m]"
   sleep 1s
   tput cuu1
   tput dl1
   echo -ne "\033[1;33m ["
done
echo -e "\033[1;33m]\033[1;31m -\033[1;32m 100%\033[1;37m"
}

menu_ssl () {
tput clear
pres_adm
echo -e "${lor2}            SSL MANAGER REMASTERIZADO"
msg -bar
[[ $(netstat -nplt |grep 'stunnel4') ]] && sessl="DETENER STUNNEL4 ${lor2}[◉] " || sessl="INICIAR STUNNEL4 ${lor1}[◉] "
[[ $(netstat -nplt |grep 'stunnel5') ]] && sessl5="DETENER STUNNEL5 ${lor2}[◉] " || sessl5="INICIAR STUNNEL5 ${lor1}[◉] "
echo -e "${lor7}[${lor2}1${lor7}] ${lor7} INSTALAR SSL STUNNEL4"
echo -e "${lor7}[${lor2}2${lor7}] ${lor7} DESINTALAR SSL STUNNEL4 "
echo -e "${lor7}[${lor2}3${lor7}] ${lor7} AÑADIR NUEVO PUERTO "
echo -e "${lor7}[${lor2}4${lor7}] ${lor7} $sessl "
echo -e "\e[1;33m ▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎\e[0m"
echo -e "${lor7}[${lor2}5${lor7}] ${lor7} INSTALAR STUNNEL5 DIRECTO"
echo -e "${lor7}[${lor2}6${lor7}] ${lor7} DESINTALAR STUNNEL5 "
echo -e "${lor7}[${lor2}7${lor7}] ${lor7} $sessl5 "
echo -e "\e[1;33m ▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎\e[0m"
echo -e "${lor7}[${lor2}8${lor7}] ${lor7} ACTIVAR CERTIFICADO MANUAL ZERO-SSL"
echo -e "${lor7}[${lor2}9${lor7}] ${lor7} ACTIVAR CERTIFICADO WEB ZIP"
echo -e "\e[1;33m ▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎▪︎\e[0m"
echo -e "${lor7}[${lor2}10${lor7}] ${lor7} INSTALAR WEBSOCKET_PYTHON"
echo -e "${lor7}[${lor2}11${lor7}] ${lor7} DESACTIVAR PUERTOS WEBSOCKET_PYTHON "
msg -bar
echo -e "${lor7}[${lor2}0${lor7}] ${lor3}==>${lor1} SALIR DEL PROTOCOLO "
msg -bar
read -p " SELECCIONA UNA OPCION: " opci
case $opci in

#OPCION 1
1)
if [ -f /etc/stunnel/stunnel.conf ]; then
echo;echo -e "${lor1}  YA ESTA INSTALADO" 
else
echo;echo -e "${lor7} Local port  ${lor6}"
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
read -p " :" -e -i $pt PT
echo;echo -e "${lor7} Listen-SSL  ${lor6}"
read -p " :" sslpt
if [ -z $sslpt ]; then
echo;echo -e "${lor1}  PUERTO INVALIDO"  
else 
if (echo $sslpt | egrep '[^0-9]' &> /dev/null);then
echo;echo -e "${lor1}  DEBES INGRESAR UN NUMERO" 
else
if lsof -Pi :$sslpt -sTCP:LISTEN -t >/dev/null ; then
echo;echo -e "${lor1}  EL PUERTO YA ESTA EN USO"  
else
inst_ssl () {
apt-get purge stunnel4 -y 
apt-get purge stunnel -y
apt-get install stunnel -y
apt-get install stunnel4 -y
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
echo -e "cert = /etc/stunnel/stunnel.pem\nclient = no\nsocket = a:SO_REUSEADDR=1\nsocket = l:TCP_NODELAY=1\nsocket = r:TCP_NODELAY=1\n\n[stunnel]\nconnect = 127.0.0.1:${PT}\naccept = ${sslpt}" > /etc/stunnel/stunnel.conf
openssl genrsa -out key.pem 2048 > /dev/null 2>&1
(echo br; echo br; echo uss; echo speed; echo pnl; echo ; echo )|openssl req -new -x509 -key key.pem -out cert.pem -days 1095 > /dev/null 2>&1
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
rm -rf key.pem;rm -rf cert.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
service stunnel restart
service stunnel4 start
}

fun_bar 'inst_ssl'
echo;echo -e "${lor2}  SSL STUNNEL INSTALADO " 
fi;fi;fi;fi
;;

#OPCION 2
2)
del_ssl () {
service stunnel4 stop
apt-get remove stunnel4 -y
apt-get purge stunnel4 -y
apt-get purge stunnel -y
rm -rf /etc/stunnel
rm -rf /etc/stunnel/stunnel.conf
rm -rf /etc/default/stunnel4
rm -rf /etc/stunnel/stunnel.pem
}

fun_bar 'del_ssl'
echo;echo -e "${lor2}  SSL STUNNEL FUE REMOVIDO " 
;;

#OPCION 3
3)
if [ -f /etc/stunnel/stunnel.conf ]; then 
echo;echo -e "${lor7}Ingresa un nombre para el SSL a Redireccionar${lor6}"
read -p " :" -e -i stunnel namessl
echo;echo -e "${lor7}Ingresa el puerto de Servicio a enlazar${lor6}"
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
read -p " :" -e -i $pt PT
echo;echo -e "${lor7}Ingresa el Nuevo Puerto SSL${lor6}"
read -p " :" sslpt
if [ -z $sslpt ]; then
echo;echo -e "${lor1}  PUERTO INVALIDO"  
else 
if (echo $sslpt | egrep '[^0-9]' &> /dev/null);then
echo;echo -e "${lor1}  DEBES INGRESAR UN NUMERO" 
else
if lsof -Pi :$sslpt -sTCP:LISTEN -t >/dev/null ; then
echo;echo -e "${lor1}  EL PUERTO YA ESTA EN USO"  
else
addgf () {		
echo -e "\n[$namessl] " >> /etc/stunnel/stunnel.conf
echo "connect = 127.0.0.1:$PT" >> /etc/stunnel/stunnel.conf 
echo "accept = $sslpt " >> /etc/stunnel/stunnel.conf 
service stunnel4 restart 1> /dev/null 2> /dev/null
service stunnel restart 1> /dev/null 2> /dev/null
sleep 2
}
fun_bar 'addgf'
echo;echo -e "${lor2} NUEVO PUERTO AÑADIDO  $sslpt !${lor7}"
fi;fi;fi
else
echo;echo -e "${lor1} SSL STUNEEL NO INSTALADO !${lor7}"
fi
;;

#OPCION 4
4)
if [ -f /etc/stunnel/stunnel.conf ];then
if netstat -nltp|grep 'stunnel4' > /dev/null; then
service stunnel stop 1> /dev/null 2> /dev/null
service stunnel4 stop 1> /dev/null 2> /dev/null
echo;echo -e "${lor1} SERVICIO DETENIDO "
else
service stunnel start 1> /dev/null 2> /dev/null
service stunnel4 start 1> /dev/null 2> /dev/null
echo;echo -e "${lor2} SERVICIO INICIADO "
fi
else
echo;echo -e "${lor1} SSL STUNNEL NO ESTA INSTALADO "
fi
;;

#OPCION 5
5)
int_sl5 () {
apt-get update -y
apt-get install openssh-server -y
apt-get install curl -y
apt-get install openssh-client -y
apt install gcc g++ build-essential libreadline-dev zlib1g-dev linux-headers-generic -y
cd /opt
wget https://www.stunnel.org/archive/5.x/stunnel-5.60.tar.gz
tar xzf stunnel-5.60.tar.gz
cd stunnel-5.60
./configure
make
make install
make cert
touch /usr/local/etc/stunnel/stunnel.conf
echo "setuid = stunnel " >> /usr/local/etc/stunnel/stunnel.conf
echo "setgid = stunnel " >> /usr/local/etc/stunnel/stunnel.conf
echo "chroot = /var/lib/stunnel " >> /usr/local/etc/stunnel/stunnel.conf
echo "pid = /stunnel.pid " >> /usr/local/etc/stunnel/stunnel.conf
echo "client = no " >> /usr/local/etc/stunnel/stunnel.conf
echo "[ssh] " >> /usr/local/etc/stunnel/stunnel.conf
echo "cert = /usr/local/etc/stunnel/stunnel.pem " >> /usr/local/etc/stunnel/stunnel.conf
echo "accept = 443 " >> /usr/local/etc/stunnel/stunnel.conf
echo "connect = 127.0.0.1:22222" >> /usr/local/etc/stunnel/stunnel.conf
useradd -s /bin/false -r stunnel
mkdir /var/lib/stunnel
chown stunnel:stunnel /var/lib/stunnel
cp /usr/local/share/doc/stunnel/examples/stunnel.init /etc/init.d/stunnel5
chmod 755 /etc/init.d/stunnel5
cp /usr/local/share/doc/stunnel/examples/stunnel.service /etc/systemd/system/stunnel5.service
systemctl stop stunnel4
systemctl disable stunnel4
systemctl start stunnel5
systemctl enable stunnel5
}
clear&&clear
pres_adm
if [ -f /etc/stunnel/stunnel.conf ]; then
echo; echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo -e "\e[1;33m ...HAY UNA INSTALACION STUNNEL EN TU SISTEMA... \e[0m"
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo; echo -e "\e[1;31m ▪︎Si Stunnel4 esta instalado en su sistema,\n Esta nueva Instalación detendrá SSL4 para,\n Habilitar a la nueva conexión SSL5 Directo▪︎ \e[0m"
sleep 0.5
echo; echo -e "\e[1;33m DESEAS CONTINUAR? : \e[0m"
while [[ ${yesno} != @(s|S|y|Y|n|N) ]]; do
read -p " [S/N]: " yesno
tput cuu1 && tput dl1
done
if [[ ${yesno} = @(s|S|y|Y) ]]; then
echo; echo -e "\e[1;32m INSTALANDO STUNNEL5 DIRECTO....\e[0m"
fun_bar 'int_sl5'
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo -e "\e[1;32m STUNNEL5 HA SIDO INSTALADO!!! \e[0m"
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
sleep 0.5
echo; echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo -e "\033[1;32m            Puertos Disponibles / En ejecucion                \033[0m"
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
netstat -tulpn | awk -vOFS='\t' '/^tcp/{print $4,$7} /^udp/{print $4,$6}' | grep "$filter"
rm stunnel5
rm -r stunnel5
read enter
fi
else
echo; echo -e "\e[1;32m INSTALANDO STUNNEL5 DIRECTO....\e[0m"
fun_bar 'int_sl5'
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo -e "\e[1;32m STUNNEL5 HA SIDO INSTALADO!!! \e[0m"
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
sleep 0.5
echo; echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
echo -e "\033[1;32m            Puertos Disponibles / En ejecucion                \033[0m"
echo -e "\033[1;30m-----------------------------------------------------------\033[0m"
netstat -tulpn | awk -vOFS='\t' '/^tcp/{print $4,$7} /^udp/{print $4,$6}' | grep "$filter"
rm stunnel5
rm -r stunnel5
read enter
fi
;;

#OPCION 6
6)
fun_bar 'del_ssl5'
echo;echo -e "${lor2}  SERVICIO STUNNEL5 FUE REMOVIDO " 
del_ssl5 () {
service stunnel5 stop
apt-get remove stunnel5 -y
apt-get purge stunnel5 -y
apt-get purge stunnel -y
rm -rf /etc/stunnel
rm -rf /etc/stunnel/stunnel.conf
rm -rf /etc/default/stunnel5
rm -rf /etc/stunnel/stunnel.pem
}
;;

#OPCION 7
7)
if [ -f /etc/stunnel/stunnel.conf ];then
if netstat -nltp|grep 'stunnel5' > /dev/null; then
service stunnel stop 1> /dev/null 2> /dev/null
service stunnel5 stop 1> /dev/null 2> /dev/null
echo;echo -e "${lor1} SERVICIO DETENIDO "
else
service stunnel start 1> /dev/null 2> /dev/null
service stunnel5 start 1> /dev/null 2> /dev/null
echo;echo -e "${lor2} SERVICIO INICIADO "
fi
else
echo;echo -e "${lor1} STUNNEL5 NO ESTA INSTALADO "
fi
;;

#OPCION 8
8)
if [ -f /etc/stunnel/stunnel.conf ]; then
insapa2(){
for pid in $(pgrep python);do
kill $pid
done
for pid in $(pgrep apache2);do
kill $pid
done
service dropbear stop
apt install apache2 -y
echo "Listen 80
<IfModule ssl_module>
        Listen 443
</IfModule>
<IfModule mod_gnutls.c>
        Listen 443
</IfModule> " > /etc/apache2/ports.conf
service apache2 restart
}

fun_bar 'insapa2'
echo;echo -e "${lor7} VERIFICA UN DOMINIO${lor6}"
read -p " KEY:" keyy
echo
read -p " DATA:" dat2w
mkdir -p /var/www/html/.well-known/pki-validation/
datfr1=$(echo "$dat2w"|awk '{print $1}')
datfr2=$(echo "$dat2w"|awk '{print $2}')
datfr3=$(echo "$dat2w"|awk '{print $3}')
echo -ne "${datfr1}\n${datfr2}\n${datfr3}" >/var/www/html/.well-known/pki-validation/$keyy.txt
echo;echo -e "${lor3} VERIFICA EN LA PAGINA DE ZEROSSL ${lor7}"
read -p " ENTER TO CONTINUE"
echo;echo -e "${lor7} LINK DEL CERTIFICADO ${lor6}"
echo -e "${lor6} LINK ${lor1}> ${lor7}\c"
read linksd
inscerts(){
wget $linksd -O /etc/stunnel/certificado.zip
cd /etc/stunnel/
unzip certificado.zip 
cat private.key certificate.crt ca_bundle.crt > stunnel.pem
service stunnel restart
service stunnel4 restart
}

fun_bar 'inscerts'
echo;echo -e "${lor2} CERTIFICADO INSTALADO ${lor7}" 
else
echo;echo -e "${lor1} SSL STUNNEL NO ESTA INSTALADO "
fi
;;

#OPCION 9
9)
 [[ $(mportas|grep stunnel4|head -1) ]] && {
 echo -e "\\033[1;33m $(fun_trans  " ¡¡¡ Deteniendo Stunnel !!!")"
 msg -bar
 service stunnel4 stop > /dev/null 2>&1
 apt-get purge stunnel4 -y &>/dev/null && echo -e "\\e[31m DETENIENDO SERVICIO SSL" | pv -qL10
 apt-get remove stunnel4 &>/dev/null
 rm -rf /etc/stunnel/stunnel.conf
 rm -rf /etc/stunnel/private.key
 rm -rf /etc/stunnel/certificate.crt
 rm -rf /etc/stunnel/ca_bundle.crt
 msg -bar
 echo -e "\\033[1;33m $(fun_trans  " ¡¡¡ Detenido Con Exito !!!")"
 msg -bar
 return 0
 }
 clear
 msg -bar
 echo -e "\\033[1;33m $(fun_trans  " Seleccione una puerta de redirección interna.")"
 echo -e "\\033[1;33m $(fun_trans  " Un puerto SSH/DROPBEAR/SQUID/OPENVPN/PYTHON")"
 msg -bar
          while true; do
          echo -ne "\\033[1;37m"
          read -p " Puerto Local: " redir
 		 echo ""
          if [[ ! -z $redir ]]; then
              if [[ $(echo $redir|grep [0-9]) ]]; then
                 [[ $(mportas|grep $redir|head -1) ]] && break || echo -e "\\033[1;31m $(fun_trans  " ¡¡¡ Puerto Invalido !!!")"
              fi
          fi
          done
 msg -bar
 DPORT="$(mportas|grep $redir|awk '{print $2}'|head -1)"
 echo -e "\\033[1;33m $(fun_trans  " Ahora Que Puerto sera SSL")"
 msg -bar
     while true; do
 	echo -ne "\\033[1;37m"
     read -p " Puerto SSL: " SSLPORT
 	echo ""
     [[ $(mportas|grep -w "$SSLPORT") ]] || break
     echo -e "\\033[1;33m $(fun_trans  " ¡¡¡ Esta Puerta Está en Uso !!!")"
     unset SSLPORT
     done
 msg -bar
 echo -e "\\033[1;33m $(fun_trans  " ¡¡¡ Instalando SSL !!!")"
 msg -bar
 apt-get install stunnel4 -y &>/dev/null && echo -e "\\e[32m INSTALANDO SSL" | pv -qL10
 clear
 echo -e "client = no\\n[SSL]\\ncert = /etc/stunnel/stunnel.pem\\naccept = ${SSLPORT}\\nconnect = 127.0.0.1:${DPORT}" > /etc/stunnel/stunnel.conf
 msg -bar
 echo -e "\\e[1;37m ACONTINUACION DEBES TENER LISTO EL LINK DEL CERTIFICADO.zip\\n VERIFICAR CERTIFICADO EN ZEROSSL, DESCARGALO Y SUBELO\\n EN TU GITHUB O DROPBOX !!!"
 msg -bar
 read -p " Enter to Continue..."
 clear
 ####Cerrificado ssl/tls#####
 echo
 msg -bar
 echo -e "\\e[1;33m👇 LINK DEL CERTIFICADO.zip 👇           \\n \\e[0m"
 echo -e "\\e[1;36m LINK \\e[37m: \\e[34m\\c "
 #extraer certificado.zip
 read linkd
 wget $linkd &>/dev/null -O /etc/stunnel/certificado.zip
 cd /etc/stunnel/
 unzip certificado.zip &>/dev/null
 cat private.key certificate.crt ca_bundle.crt > stunnel.pem
 rm -rf certificado.zip
 sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
 service stunnel restart > /dev/null 2>&1
 service stunnel4 restart &>/dev/null
 msg -bar
 echo -e "${cor[4]} CERTIFICADO INSTALADO CON EXITO \\e[0m" 
 msg -bar
 ;;

#OPCION 10
10)
tput clear
echo
msg -bar
echo -e "\033[1;33m      WEBSOCKET SSL_PYTHON (ADMATRIX-PRO) "
msg -bar
echo -e "\033[1;37m   🂡 Requiere Las Puertas Libres: 80 & 443 🂡  "
echo
msg -bar
echo -e "\033[1;33m      ▪︎ INSTALANDO SSL EN PUERTO: 443 ▪︎  "

inst_ssl () {
pkill -f stunnel4
pkill -f stunnel
pkill -f 443
apt-get purge stunnel4 -y
apt-get purge stunnel -y
apt-get install stunnel4 -y
apt-get install stunnel -y
pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)
echo -e "cert = /etc/stunnel/stunnel.pem\nclient = no\nsocket = a:SO_REUSEADDR=1\nsocket = l:TCP_NODELAY=1\nsocket = r:TCP_NODELAY=1\n\n[stunnel]\nconnect = 127.0.0.1:${pt}\naccept = 443" > /etc/stunnel/stunnel.conf
openssl genrsa -out key.pem 2048 > /dev/null 2>&1
(echo br; echo br; echo uss; echo speed; echo pnl; echo Razhiel; echo @xprorazh.ml)|openssl req -new -x509 -key key.pem -out cert.pem -days 1095 > /dev/null 2>&1
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
service stunnel restart
service stunnel4 start
}

fun_bar 'inst_ssl'
msg -bar
echo -e "\033[1;33m   ▪︎ CONFIGURANDO PYTHON EN PUERTO: 80 ▪︎ "

inst_py () {
pkill -f 80
pkill python
apt install python -y
apt install screen -y

pt=$(netstat -nplt |grep 'sshd' | awk -F ":" NR==1{'print $2'} | cut -d " " -f 1)

 cat <<EOF > proxy.py
import socket, threading, thread, select, signal, sys, time, getopt
# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 1080
PASS = ''
# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = "127.0.0.1:$pt"
RESPONSE = 'HTTP/1.1 101 Switching Protocols \r\n\r\n'
 
class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()
    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			
class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)
    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            
            if hostPort == '':
                hostPort = DEFAULT_HOST
            split = self.findHeader(self.client_buffer, 'X-Split')
            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')
        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)
    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''
        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')
        if aux == -1:
            return ''
        return head[:aux];
    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 80
        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)
    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''
        self.server.printLog(self.log)
        self.doCONNECT()
    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break
def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 1080'
def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)
    
def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    
    print "\n ==============================\n"
    print "\n         PYTHON PROXY          \n"
    print "\n ==============================\n"
    print "corriendo ip: " + LISTENING_ADDR
    print "corriendo port: " + str(LISTENING_PORT) + "\n"
    print "Se ha Iniciado Por Favor Cierre el Terminal\n"
    
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break
    
if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOF
screen -dmS pythonwe python proxy.py -p 80&
}

fun_bar 'inst_py'
rm -rf proxy.py
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT

echo -e "ps x | grep 'pythonwe' | grep -v 'grep' || screen -dmS pythonwe python proxy.py -p 80" >> /etc/autostart

echo -e "\033[1;32m         INSTALACION COMPLETADA "
;;

#OPCION 11
11)
msg -bar 
echo
echo -e "\e[1;33m      DETENIENDO SERVICIOS WEBSOCKED SSL+PYTHON\e[0m" 
service stunnel4 stop > /dev/null 2>&1 
apt-get purge stunnel4 -y &>/dev/null 
apt-get purge stunnel -y &>/dev/null 
kill -9 $(ps aux |grep -v grep |grep -w "proxy.py"|grep dmS|awk '{print $2}') &>/dev/null 
rm /etc/newadm/PySSL.log &>/dev/null 
echo 
echo -e  "\e[1;32m           LOS SERVICIOS SE HAN DETENIDO\e[0m" 
msg -bar
;;

#OPCION SALIDA
0)
exit
;;

*)
echo
echo -e "\e[1;31m\n Elige Una Opcion Habilitada... \e[0m"
sleep 1
menu_ssl
;;
esac
}
menu_ssl
#fin
