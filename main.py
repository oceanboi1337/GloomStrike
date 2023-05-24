import argparse, json, sys, time, os, socket, ipaddress
import network

def f_network(args):

    if args.port_scan:

        port_scanner = network.PortScanner(args.target, ports=args.port)
        port_scanner.scan(background=True)

        return 

    pass

def f_hashcrack(args):
    pass

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Choose output format', default='')
    parser.add_argument('-t', '--threads', help='Amount of threads to use')

    subparsers = parser.add_subparsers(dest='module')

    p_network = subparsers.add_parser('network', help='Enable the network module')
    p_network.add_argument('-hd', '--discovery', help='Enable host discovery scan', action='store_true')
    p_network.add_argument('--arp', help='Will use ARP scan for host discovery', action='store_true')
    p_network.add_argument('--icmp', help='Will use ICMP requests for host discovery', action='store_true')
    p_network.add_argument('-ps', '--port-scan', help='Enable port scanning', action='store_true')
    p_network.add_argument('--tcp', help='Port scanner will use TCP (Default)', action='store_true')
    #p_network.add_argument('--udp', help='Port scanner will use UDP', action='store_true')
    p_network.add_argument('-p', '--port', help='Which ports to scan <80,443>')
    p_network.add_argument('target', help='The target CIDR / Host to scan', type=str)

    p_hashcrack = subparsers.add_parser('hashcrack', help='Enables the hashcrack module')
    p_hashcrack.add_argument('-f', '--hash', help='Path to the file containing the hashes')
    p_hashcrack.add_argument('-w', '--wordlist', help='Path to the wordlist')

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)

    match args.module.lower():

        case 'network': result = f_network(args)
        case 'hashcrack': result = f_hashcrack(args)