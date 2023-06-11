# GloomStrike
## The most elite hecker tool

### Network Mapper

#### Host Scanner
How to run a ARP Host Scan:
>python main.py network -d 192.168.1.0/24 --arp

How to run a ICMP Host Scan:
>python main.py network -d 192.168.1.0/24 --icmp

#### Port Scanner
How to run a Port Scan:
>python main.py network -ps -p 21,22,53,80 example.com

Scans all ports:
>python main.py network -ps -p - example.com

Scans common ports:
>python main.py network -ps example.com

#### Web Fuzzer
How to fuzz files and directories:
>python main.py fuzzer -d wordlists/common-dirs.txt -f wordlists/common-files.txt http://example.com/ --threads 10 --depth 2

#### Hash Cracker
List all available algorithms:
>python main.py hashcrack -al

How to crack a hash:
>python main.py hashcrack -f hashes.txt -w wordlists/rockyou.txt -a md5 -pf potfile.txt

#### Login Checker
How to bruteforce a login page:
>python main.py checker --params 'username=$USERNAME&password=$PASSWORD' -u usernames.txt -p passwords.txt http://example.com/login

How to bruteforce a login page with CSRF tokens:
>python main.py checker --params 'username=$USERNAME&password=$PASSWORD' -u usernames.txt -p passwords.txt --csrf-url http://192.168.1.50:5000/login --csrf csrf-token --threads 10 -u usernames.txt -p passwords.txt http://example.com/login