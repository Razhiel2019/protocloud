#!/bin/bash
#31/03/2022

clear
#colores
lor1='\033[1;31m';lor2='\033[1;32m';lor3='\033[1;33m';lor4='\033[1;34m';lor5='\033[1;35m';lor6='\033[1;36m';lor7='\033[1;37m'
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
SCPfrm="/etc/ger-frm" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="/etc/ger-inst" && [[ ! -d ${SCPinst} ]] && exit
apt-get install python -y > /dev/null 2>&1
apt-get install iptables-persistent -y &>/dev/null 
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

meu_ip () {
MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
[[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
}

directssl () {
clear
msg -bar
echo -e "\033[1;33m       WEBSOCKET DIRECT_STUNNEL_PYTHON "
echo -e "\033[1;37m       Requiere Las Puertas Libres: 80 & 443  "
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
(echo br; echo br; echo uss; echo speed; echo pnl; echo Razhiel; echo @)|openssl req -new -x509 -key key.pem -out cert.pem -days 1095 > /dev/null 2>&1
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
service stunnel restart
service stunnel4 start
}
inst_ssl &>/dev/null
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

inst_py &>/dev/null
rm -rf proxy.py
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT

echo -e "ps x | grep 'pythonwe' | grep -v 'grep' || screen -dmS pythonwe python proxy.py -p 80" >> /etc/autostart
msg -bar
echo
echo -e "\e[1;33m     ================================\e[0m"
echo -e "\e[1;33m     ====== WS DIRECT_CDN SSL  =====\e[0m"
echo -e "\e[1;33m     ================================\e[0m"
echo -e "\e[1;33m     Inicia Ip en Port Stunnel-4: 443     \e[0m"
echo -e "\e[1;33m     Inicia ip en Port Python: 80         \e[0m"
echo -e "\e[1;33m     ================================\e[0m"
echo
msg -bar
echo
echo -e "\033[1;32m         INSTALACION COMPLETADA "
echo "      Presione enter para finalizar... "
read enter
}

directdrpend () {
msg -bar
echo -e "\e[1;33m     ================================\e[0m"
echo -e "\e[1;33m     ====== WS DIRECT_CDN SSH =====\e[0m"
echo -e "\e[1;33m     ================================\e[0m"
echo -e "\e[1;33m     Inicia Ip en Port SSH: $porta_socket  \e[0m"
echo -e "\e[1;33m     Inicia ip en Port Python: 80         \e[0m"
echo -e "\e[1;33m     ================================\e[0m"
msg -bar
echo
echo -e "\033[1;32m         INSTALACION COMPLETADA "
echo "      Presione enter para finalizar... "
read enter
}

remove_fun () {
msg -bar
echo -e "$(fun_trans  " DETENIENDO CONEXIONES WS DIRECT_CDN")"
msg -bar
pidproxy1=$(ps x | grep "wsproxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy1 ]] && pid_kill $pidproxy1
pidproxy2=$(ps x | grep "proxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy2 ]] && pid_kill $pidproxy2
service stunnel4 stop > /dev/null 2>&1 
apt-get purge stunnel4 -y &>/dev/null 
apt-get purge stunnel -y &>/dev/null 
echo -e "\033[1;91m  $(fun_trans  " PUERTOS DETENIDOS Y DESHABILITADOS")"
msg -bar
rm -rf /etc/newadm/PortPD.log
echo "" > /etc/newadm/PortPD.log
py=$(cat /etc/newadm/py.log|cut -d'|' -f1)
systemctl stop python.${py} &>/dev/null
systemctl disable python.${py} &>/dev/null
rm /etc/systemd/system/python.${py}.service &>/dev/null
exit 0
}

### MENU PRINCIPAL
IntWs () {
pidproxy1=$(ps x | grep "wsproxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy1 ]] && P1="\033[1;32m[ON] " || P1="\033[1;31m[OFF] "
pidproxy2=$(ps x | grep "proxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy2 ]] && P2="\033[1;32m[ON] " || P2="\033[1;31m[OFF] "
tput clear
msg -bar
echo -e "\033[1;33m $(fun_trans  "  WEBSOCKET DIRECT | ADM-JMNIC")"
msg -bar
echo -e "${cor[4]} [1] > \033[1;36m$(fun_trans  "WS DIRECT_CDN \e[1;49;32m[SSH/Drop]\e[0m") $P1"
echo -e "${cor[4]} [2] > \033[1;36m$(fun_trans  "WS DIRECT_CDN \e[1;49;36m[Stunnel] \e[0m") $P2"
echo -e "${cor[4]} [3] > \033[1;33m$(fun_trans  "DETENER PUERTOS WEBSOCKET")"
msg -bar
echo -e "${cor[4]} [0] > \033[93;101m$(fun_trans  " SALIR ")"
msg -bar
IP=(meu_ip)
while [[ -z $portproxy || $portproxy != @(0|[1-3]) ]]; do
echo -ne "$(fun_trans  " Digite Una Opcion"): \033[1;37m" && read portproxy
tput cuu1 && tput dl1
case $portproxy in
    2)directssl;;
    3)remove_fun && return;;
    0)return;;
 esac
echo
echo -e "\033[1;33m       WEBSOCKET DIRECT_CDN SSH/DROPBEAR"
msg -bar
echo
echo -e "\e[1;37m 《 Se Enlazara Un Puerto SSH/Dropbear con Python_80 》 \e[0m"
echo -e "\e[1;31m Es Necesario Haber Instalado Previamente El Protocolo A enlazar...\e[0m"
echo
while [[ -z $porta_socket || ! -z $(mportas|grep -w $porta_socket) ]]; do
echo -ne "\e[1;37m Digite Un Puerto Activo: \033[0m" && read porta_socket
tput cuu1 && tput dl1
[[ $(mportas|grep -w "$porta_socket") ]] || break
echo -e "\e[1;31m ESTE PUERTO YA ESTÁ EN USO \e[0m"
echo ""
unset porta_socket
done
echo -e "\e[1;97m        《 Introduzca Un Mini-Banner 》\e[0m"
msg -bar
echo -ne " Introduzca el texto en estado plano o en HTML: \033[1;37m\n" && read texto_soket
[[ "$texto_soket" = "" ]]&& texto_soket='<span style="color: #ff0000;"><strong><span style="color: #ff9900;">By:</span>-<span style="color: #008000;"> ADM-JMNIC</span>- @Razhiel</strong></span>'
sleep 0.5s
done
    case $portproxy in
    1)screen -dmS screen python ${SCPinst}/wsproxy.py "$porta_socket" "$texto_soket"
    directdrpend;;
    *);;
    esac
echo
echo -e "\033[1;92m|>>> Procedimiento COMPLETO <<<|"
msg -bar
}
IntWs
#fin
