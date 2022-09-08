#!/bin/bash

clear; clear
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
#colores
lor1='\033[1;31m';lor2='\033[1;32m';lor3='\033[1;33m';lor4='\033[1;34m';lor5='\033[1;35m';lor6='\033[1;36m';lor7='\033[1;37m'
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

tcpbypass_fun () {
[[ -e $HOME/socks ]] && rm -rf $HOME/socks > /dev/null 2>&1
[[ -d $HOME/socks ]] && rm -rf $HOME/socks > /dev/null 2>&1
cd $HOME && mkdir socks > /dev/null 2>&1
cd socks
patch="https://www.dropbox.com/s/b2qx4feqv05h4l2/backsocz"
arq="backsocz"
wget $patch -o /dev/null
unzip $arq > /dev/null 2>&1
mv -f ./ssh /etc/ssh/sshd_config && service ssh restart 1> /dev/null 2>/dev/null
mv -f sckt$(python3 --version|awk '{print $2}'|cut -d'.' -f1,2) /usr/sbin/sckt
mv -f scktcheck /bin/scktcheck
chmod +x /bin/scktcheck
chmod +x  /usr/sbin/sckt
rm -rf $HOME/socks
cd $HOME
msg="$2"
[[ $msg = "" ]] && msg="@jmnic"
portxz="$1"
[[ $portxz = "" ]] && portxz="8080"
screen -dmS sokz scktcheck "$portxz" "$msg" > /dev/null 2>&1
}

gettunel_fun () {
echo "master=ADM-JMNIC" > ${SCPinst}/pwd.pwd
while read service; do
[[ -z $service ]] && break
echo "127.0.0.1:$(echo $service|cut -d' ' -f2)=$(echo $service|cut -d' ' -f1)" >> ${SCPinst}/pwd.pwd
done <<< "$(mportas)"
screen -dmS getpy python ${SCPinst}/PGet.py -b "0.0.0.0:$1" -p "${SCPinst}/pwd.pwd"
 [[ "$(ps x | grep "PGet.py" | grep -v "grep" | awk -F "pts" '{print $1}')" ]] && {
 echo -e "$(fun_trans  "Gettunel Iniciado com Sucesso")"
 msg -bar
 echo -ne "$(fun_trans  "Sua Senha Gettunel e"):"
 echo -e "\033[1;32m ADM_TYPHON"
 msg -bar
 } || echo -e "$(fun_trans  "Gettunel nao foi iniciado")"
 msg -bar
}

PythonDic_fun () {
echo
echo -e "\033[1;97m * Selecciona Puerto Local *\033[1;37m" 
msg -bar
echo -ne " Digite Puerto SSH/DROPBEAR activo: \033[1;37m" && read puetoantla 
 msg -bar
(
less << PYTHON  > /etc/ger-inst/PDirect.py
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
  LISTENING_PORT = sys.argv[1]
else:
  LISTENING_PORT = 80  
#Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:$puetoantla'
RESPONSE = 'HTTP/1.1 200 <strong>$texto_soket</strong>\r\nContent-length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n'
#RESPONSE = 'HTTP/1.1 200 Hello_World!\r\nContent-length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n'  # lint:ok

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
        intport = int(self.port)
        self.soc.bind((self.host, intport))
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
                conn.start()
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
                port = $puetoantla
            else:
                port = sys.argv[1]

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
    print '       proxy.py -b 0.0.0.0 -p 80'

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
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

#######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()

PYTHON
) > $HOME/proxy.log

chmod +x /etc/ger-inst/PDirect.py

screen -dmS pydic-"$porta_socket" python ${SCPinst}/PDirect.py "$porta_socket" "$texto_soket" && echo ""$porta_socket" "$texto_soket"" >> /etc/newadm/PortPD.log
}

wsdirectssl () {
tput clear
echo
msg -bar
echo -e "\033[1;33m            WEBSOCKET SSL_PYTHON "
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
(echo br; echo br; echo uss; echo speed; echo pnl; echo Razhiel; echo @xprorazh.ml)|openssl req -new -x509 -key key.pem -out cert.pem -days 1095 > /dev/null 2>&1
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
echo -e "\e[1;33m     ====== SS + PYTHON PROXY  =====\e[0m"
echo -e "\e[1;33m     ================================\e[0m"
echo -e "\e[1;33m     Inicia Ip en Port Stunnel-4: 443     ==\e[0m"
echo -e "\e[1;33m     Inicia ip en Port Python: 80         ==\e[0m"
echo -e "\e[1;33m     ================================\e[0m"
echo
msg -bar
echo
echo -e "\033[1;32m         INSTALACION COMPLETADA "
echo "      Presione enter para finalizar... "
}


pid_kill () {
[[ -z $1 ]] && refurn 1
pids="$@"
for pid in $(echo $pids); do
kill -9 $pid &>/dev/null
done
}
remove_fun () {
echo -e "$(fun_trans  " Deteniendo Puertos Python/WS")"
msg -bar
pidproxy=$(ps x | grep "PPub.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy ]] && pid_kill $pidproxy
pidproxy2=$(ps x | grep "PPriv.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy2 ]] && pid_kill $pidproxy2
pidproxy3=$(ps x | grep "PDirect.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy3 ]] && pid_kill $pidproxy3
pidproxy4=$(ps x | grep "POpen.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy4 ]] && pid_kill $pidproxy4
pidproxy5=$(ps x | grep "PGet.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy5 ]] && pid_kill $pidproxy5
pidproxy6=$(ps x | grep "scktcheck" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy6 ]] && pid_kill $pidproxy6
pidproxy7=$(ps x | grep "wsproxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy7 ]] && pid_kill $pidproxy7
pidproxy8=$(ps x | grep "proxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy8 ]] && pid_kill $pidproxy8
service stunnel4 stop > /dev/null 2>&1 
apt-get purge stunnel4 -y &>/dev/null 
apt-get purge stunnel -y &>/dev/null 
kill -9 $(ps aux |grep -v grep |grep -w "proxy.py"|grep dmS|awk '{print $2}') &>/dev/null 
rm /etc/newadm/proxy.log &>/dev/null 
echo
echo -e "\033[1;91m  $(fun_trans  " PUERTOS DETENIDOS!!!")"
msg -bar
rm -rf /etc/newadm/PortPD.log
echo "" > /etc/newadm/PortPD.log
exit 0
}

iniciarsocks () {
clear
pidproxy=$(ps x | grep -w "PPub.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy ]] && P1="\033[1;32m[ON]" || P1="\033[1;31m[OFF]"
pidproxy2=$(ps x | grep -w  "PPriv.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy2 ]] && P2="\033[1;32m[ON]" || P2="\033[1;31m[OFF]"
pidproxy3=$(ps x | grep -w  "PDirect.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy3 ]] && P3="\033[1;32m[ON]" || P3="\033[1;31m[OFF]"
pidproxy4=$(ps x | grep -w  "POpen.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy4 ]] && P4="\033[1;32m[ON]" || P4="\033[1;31m[OFF]"
pidproxy5=$(ps x | grep "PGet.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy5 ]] && P5="\033[1;32m[ON]" || P5="\033[1;31m[OFF]"
pidproxy6=$(ps x | grep "scktcheck" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy6 ]] && P6="\033[1;32m[ON]" || P6="\033[1;31m[OFF]"
pidproxy7=$(ps x | grep "wsproxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy7 ]] && P7="\033[1;32m[ON] " || P7="\033[1;31m[OFF] "
pidproxy8=$(ps x | grep "proxy.py" | grep -v "grep" | awk -F "pts" '{print $1}') && [[ ! -z $pidproxy8 ]] && P8="\033[1;32m[ON] " || P8="\033[1;31m[OFF] "
msg -bar
echo -e "\033[1;37m $(fun_trans  " INSTALADOR SOCKS_PYTHON")| ADM_JMNIC\e[0m"
msg -bar
echo -e "${cor[4]} [1] › \033[1;37m$(fun_trans  "Socks Python SIMPLE") $P1"
echo -e "${cor[4]} [2] › \033[1;37m$(fun_trans  "Socks Python SEGURO") $P2"
echo -e "${cor[4]} [3] › \033[1;37m$(fun_trans  "Socks Python DIRETO") $P3"
echo -e "${cor[4]} [4] › \033[1;37m$(fun_trans  "Socks Python OPENVPN") $P4"
echo -e "${cor[4]} [5] › \033[1;37m$(fun_trans  "Socks Python GETTUNEL") $P5"
echo -e "${cor[4]} [6] › \033[1;37m$(fun_trans  "Socks Python TCP BYPASS") $P6"
msg -bar
echo -e "${cor[4]} [7] › \033[1;37m$(fun_trans  "WS CDN_SSH/DROP") $P7"
echo -e "${cor[4]} [8] › \033[1;37m$(fun_trans  "WS DIRECT_SSL") $P8"
msg -bar
echo -e "${cor[4]} [9] › \033[1;37m$(fun_trans  "DETENEE PUERTOS PYTHON/WS")"
echo -e "${cor[4]} [0] › \033[1;37m$(fun_trans  "VOLVER")"
msg -bar
IP=(meu_ip)
while [[ -z $portproxy || $portproxy != @(0|[1-9]) ]]; do
echo -ne "$(fun_trans  "Digite Una Opcion"): \033[1;37m" && read portproxy
tput cuu1 && tput dl1
done
 case $portproxy in
    8)wsdirectssl;;
    9)remove_fun;;
    0)return;;
 esac
echo
echo -e " Selecciona El Puerto Principal Proxy A Enlazar !!!"
msg -bar
porta_socket=
while [[ -z $porta_socket || ! -z $(mportas|grep -w $porta_socket) ]]; do
echo -ne " Digite el Puerto: \033[1;37m" && read porta_socket
tput cuu1 && tput dl1
done
echo -e "$(fun_trans  " * Introduzca su Mini-Banner *")"
msg -bar
echo -ne " Introduzca el texto de estado plano o en HTML:\n \033[1;37m" && read texto_soket
    msg -bar
    case $portproxy in
    1)screen -dmS screen python ${SCPinst}/PPub.py "$porta_socket" "$texto_soket";;
    2)screen -dmS screen python3 ${SCPinst}/PPriv.py "$porta_socket" "$texto_soket" "$IP";;
    3)PythonDic_fun;;
    4)screen -dmS screen python ${SCPinst}/POpen.py "$porta_socket" "$texto_soket";;
    5)gettunel_fun "$porta_socket";;
    6)tcpbypass_fun "$porta_socket" "$texto_soket";;
    7)screen -dmS screen python ${SCPinst}/wsproxy.py "$porta_socket" "$texto_soket";;
    esac
echo
echo -e "\033[1;34m$(fun_trans "Procedimiento COMPLETO")"
msg -bar
}
iniciarsocks
