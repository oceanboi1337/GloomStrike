import argparse, sys, hashlib
from gloomstrike import hashcrack, network, fuzzer, checker, logger

def f_network(args, logger):

    protocol = None

    if args.arp: protocol = network.Protocol.ARP
    elif args.icmp: protocol = network.Protocol.ICMP

    if args.port_scan:

        port_scanner = network.PortScanner(args.target, args.port, logger=logger)

        if port_scanner.ready:
            port_scanner.scan(background=False)

        return port_scanner._results

    if args.discovery:

        host_scanner = network.HostScanner(args.target, logger=logger)

        if host_scanner.ready:
            host_scanner.start(protocol, background=False)

        return host_scanner._results

def f_hashcrack(args, logger):

    if args.al:

        for algorithm in hashlib.algorithms_available:
            print(algorithm)

        return
    
    cracker = hashcrack.Hashcrack(logger=logger)

    if cracker.load_hashes(args.f) and cracker.load_wordlist(args.w):

        return cracker.start(args.a, background=False)
    
def f_fuzzer(args, logger):

    #url_fuzzer = fuzzer.UrlFuzzer(args.target, args.wordlist, args.timeout, args.status_code, logger=logger)
    url_fuzzer = fuzzer.UrlFuzzer(args.dirs, args.files, 'wordlists/fuzzer/extensions_common.txt', logger=logger)
    url_fuzzer.start(args.target, threads=args.threads)


def f_checker(args, logger):

    http_checker = checker.HttpChecker(args.target, args.params, args.csrf, logger)

    if http_checker.load(args.combolist, args.usernames, args.passwords, args.proxies):
        http_checker.start(threads=args.threads)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Sets verbosity level', default=0, type=int)
    parser.add_argument('-o', '--output', help='Choose output format', default='')

    subparsers = parser.add_subparsers(dest='module')

    p_network = subparsers.add_parser('network', help='Enable the network module')
    p_network.add_argument('-d', '--discovery', help='Enable host discovery scan', action='store_true')
    p_network.add_argument('-ps', '--port-scan', help='Enable port scanning', action='store_true')
    p_network.add_argument('-p', '--port', help='Which ports to scan <80,443>')
    p_network.add_argument('--arp', help='ARP scan for host discovery', action='store_true')
    p_network.add_argument('--icmp', help='ICMP scan for host discovery', action='store_true')
    p_network.add_argument('target', help='The target CIDR / Host to scan', type=str)

    p_hashcrack = subparsers.add_parser('hashcrack', help='Enable the hashcrack module')
    p_hashcrack.add_argument('-f', help='Path to the file containing a list of hashes')
    p_hashcrack.add_argument('-w', help='Path to the wordlist')
    p_hashcrack.add_argument('-a', help='The hash type')
    p_hashcrack.add_argument('-al', help='List available hashing algorithms', action='store_true')

    p_fuzzer = subparsers.add_parser('fuzzer', help='Enable the fuzzer module')
    p_fuzzer.add_argument('-f', '--files', help='Path to files wordlist', default='wordlists/fuzzer/files/common-files.txt')
    p_fuzzer.add_argument('-d', '--dirs', help='Path to directories wordlist', default='wordlists/fuzzer/dirs/raft-large-directories-lowercase.txt')
    p_fuzzer.add_argument('-t', '--timeout', help='Timeout limit for a request <seconds>')
    p_fuzzer.add_argument('-s', '--status-code', help='List of status codes to check for <200,404,401>')
    p_fuzzer.add_argument('--depth', help='Max recursive depth (Default 2)', default=0, type=int)
    p_fuzzer.add_argument('--threads', help='Amount of threads to use', default=25, type=int)
    p_fuzzer.add_argument('target', help='Target URL to fuzz')

    p_checker = subparsers.add_parser('checker', help='Enable the checker module')
    p_checker.add_argument('--proxies', help='Path to a proxylist <protocol:endpoint:port>', default=None)
    p_checker.add_argument('--csrf', help='HTML <input name="X"> tag which is used for CSRF protection <X>', default=None)
    p_checker.add_argument('--threads', help='Thread amount to use', default=10, type=int)
    p_checker.add_argument('--params', help='HTTP parameters to fill <username,password>', default='username=$USERNAME&password=$PASSWORD', required=True)
    p_checker.add_argument('-u', '--usernames', help='Path to a file with usernames')
    p_checker.add_argument('-p', '--passwords', help='Path to a file with passwords')
    p_checker.add_argument('-c', '--combolist', help='Path to a file with username:password')
    p_checker.add_argument('target', help='Target URL to check logins for')

    args = parser.parse_args()

    _logger = logger.Logger(verbose=args.verbose)

    if not args.module:

        parser.print_help()
        sys.exit(0)

    match args.module.lower():

        case 'network': result = f_network(args, _logger)
        case 'hashcrack': result = f_hashcrack(args, _logger)
        case 'fuzzer': result = f_fuzzer(args, _logger)
        case 'checker': result = f_checker(args, _logger)