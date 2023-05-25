import argparse, sys, hashcrack, network, hashlib, time
from logger import Logger

def f_network(args, logger):

    protocol = None

    if args.arp: protocol = network.Protocol.ARP
    elif args.icmp: protocol = network.Protocol.ICMP

    if args.port_scan:

        port_scanner = network.PortScanner(args.target, args.port, logger=logger)

        if port_scanner.ready:
            port_scanner.scan(background=False)

        return port_scanner.results

    if args.discovery:

        host_scanner = network.HostScanner(args.target, logger=logger)

        if host_scanner.ready:
            host_scanner.start(protocol, background=False)

        return host_scanner.results

def f_hashcrack(args, logger):

    if args.al:

        for algorithm in hashlib.algorithms_available:
            print(algorithm)

        return
    
    cracker = hashcrack.Hashcrack(logger=logger)

    if cracker.load_hashes(args.f) and cracker.load_wordlist(args.w):

        return cracker.start(args.a, background=False)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Sets verbosity level', default=0, type=int)
    parser.add_argument('-o', '--output', help='Choose output format', default='')
    parser.add_argument('-t', '--threads', help='Amount of threads to use')

    subparsers = parser.add_subparsers(dest='module')

    p_network = subparsers.add_parser('network', help='Enable the network module')
    p_network.add_argument('-d', '--discovery', help='Enable host discovery scan', action='store_true')
    p_network.add_argument('-ps', '--port-scan', help='Enable port scanning', action='store_true')
    p_network.add_argument('-p', '--port', help='Which ports to scan <80,443>')
    p_network.add_argument('--arp', help='ARP scan for host discovery', action='store_true')
    p_network.add_argument('--icmp', help='ICMP scan for host discovery', action='store_true')
    p_network.add_argument('target', help='The target CIDR / Host to scan', type=str)

    p_hashcrack = subparsers.add_parser('hashcrack', help='Enables the hashcrack module')
    p_hashcrack.add_argument('-f', help='Path to the file containing a list of hashes')
    p_hashcrack.add_argument('-w', help='Path to the wordlist')
    p_hashcrack.add_argument('-a', help='The hash type')
    p_hashcrack.add_argument('-al', help='List available hashing algorithms', action='store_true')

    args = parser.parse_args()

    logger = Logger(verbose=args.verbose)

    if not args.module:
        parser.print_help()
        sys.exit(1)

    match args.module.lower():

        case 'network': result = f_network(args, logger)
        case 'hashcrack': result = f_hashcrack(args, logger)