# GloomStrike
## The most elite hecker tool

### Network Mapper

#### Host Scanner
How to run a ARP Host Scan:
>python main.py -d 192.168.1.0/24 --arp

How to run a ICMP Host Scan:
>python main.py -d 192.168.1.0/24 --icmp

#### Port Scanner
How to run a Port Scan:
>python main.py -ps -p 21,22,53,80 example.com

Scans all ports.
>python main.py -ps -p - example.com