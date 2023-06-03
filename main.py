import argparse, sys, hashlib, time
from gloomstrike import hashcrack, network, fuzzer, checker, logger, gui
from gloomstrike.gui import routes

def f_gui(args: argparse.Namespace):

    logger.log('Starting GUI server...', level=logger.Level.INFO)

    server = gui.WebServer('127.0.0.1', 1337)

    server.add_router('/', 'index', routes.index.router)
    server.add_router('/network', 'network', routes.network.router)
    server.add_router('/scans', 'scans', routes.scans.router)
    server.add_router('/hashcrack', 'hashcrack', routes.hashcrack.router)

    if server.start():

        logger.log('Started GUI server at: {server._host}')

    while 1:
        
        time.sleep(1)

def f_network(args: argparse.Namespace):

    protocol = None

    if args.arp:    protocol = network.Protocol.ARP
    elif args.icmp: protocol = network.Protocol.ICMP

    if args.port_scan:

        port_scanner = network.PortScanner(args.target, args.port)

        if port_scanner.ready:
            port_scanner.scan(background=False)

        return port_scanner._results

    if args.discovery:

        host_scanner = network.HostScanner(args.target)

        if host_scanner.ready:
            host_scanner.start(protocol, background=False)

        return host_scanner._results

def f_hashcrack(args: argparse.Namespace):

    if args.al:

        for algorithm in hashlib.algorithms_available:
            print(algorithm)

        return
    
    cracker = hashcrack.Hashcrack(potfile=args.potfile)

    if cracker.load_hashes(args.f) and cracker.load_wordlist(args.w):

        return cracker.start(args.a, background=False)
    
def f_fuzzer(args: argparse.Namespace):

    if args.sub and args.sw:

        sub_fuzzer = fuzzer.SubFuzzer(args.target, args.sw)

        if not sub_fuzzer._load():
            logger.log('Failed to load subdomains', level=logger.Level.ERROR); return

        results = sub_fuzzer.start(args.threads, background=False)
    
    elif args.sub and not args.sw:
        logger.log('No subdomains wordlist was entered', level=logger.Level.ERROR); return
    
    elif not args.sub and not args.sw:

        #url_fuzzer = fuzzer.UrlFuzzer(args.target, args.wordlist, args.timeout, args.status_code, logger=logger)
        url_fuzzer = fuzzer.UrlFuzzer(args.dirs, args.files)
        url_fuzzer.start(args.target, threads=args.threads)


def f_checker(args: argparse.Namespace):

    if not args.csrf and args.csrf_url:
        logger.log('--csrf argument missing', level=logger.Level.ERROR); return

    if not args.csrf_url and args.csrf:
        logger.log('--csrf-url argument missing', level=logger.Level.ERROR); return

    http_checker = checker.HttpChecker(args.target, args.params, args.csrf, args.csrf_url)

    if http_checker.load(args.combolist, args.usernames, args.passwords, args.proxies):
        http_checker.start(threads=args.threads, background=False)

    return http_checker.results(format=args.output)

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
    p_hashcrack.add_argument('-pf', '--potfile', help='Path to the potlist file')

    p_fuzzer = subparsers.add_parser('fuzzer', help='Enable the fuzzer module')
    p_fuzzer.add_argument('-f', '--files', help='Path to files wordlist', default='wordlists/fuzzer/files/common-files.txt')
    p_fuzzer.add_argument('-d', '--dirs', help='Path to directories wordlist', default='wordlists/fuzzer/dirs/raft-large-directories-lowercase.txt')
    p_fuzzer.add_argument('-t', '--timeout', help='Timeout limit for a request <seconds>')
    p_fuzzer.add_argument('-s', '--status-code', help='List of status codes to check for <200,404,401>')
    p_fuzzer.add_argument('-sw', help='Path to the subdomains to fuzz')
    p_fuzzer.add_argument('--sub', help='Will use the sub domain fuzzer instead', action='store_true')
    p_fuzzer.add_argument('--depth', help='Max recursive depth (Default 2)', default=0, type=int)
    p_fuzzer.add_argument('--threads', help='Amount of threads to use', default=25, type=int)
    p_fuzzer.add_argument('target', help='Target URL to fuzz')

    p_checker = subparsers.add_parser('checker', help='Enable the checker module')
    p_checker.add_argument('--proxies', help='Path to a proxylist <protocol:endpoint:port>', default=None)
    p_checker.add_argument('--csrf', help='The HTML input name which holds the CSRF token value')
    p_checker.add_argument('--csrf-url', help='The URL to fetch the csrf-token from')
    p_checker.add_argument('--threads', help='Thread amount to use', default=10, type=int)
    p_checker.add_argument('--params', help='HTTP parameters to fill <username,password>', default='username=$USERNAME&password=$PASSWORD', required=True)
    p_checker.add_argument('-u', '--usernames', help='Path to a file with usernames')
    p_checker.add_argument('-p', '--passwords', help='Path to a file with passwords')
    p_checker.add_argument('-c', '--combolist', help='Path to a file with username:password')
    p_checker.add_argument('target', help='Target URL to check logins for')

    p_gui = subparsers.add_parser('gui', help='Enable GUI for the tool')

    args = parser.parse_args()

    logger.verbose = args.verbose

    if not args.module:

        parser.print_help()
        sys.exit(0)

    match args.module.lower():

        case 'network': result = f_network(args)
        case 'hashcrack': result = f_hashcrack(args)
        case 'fuzzer': result = f_fuzzer(args)
        case 'checker': result = f_checker(args)
        case 'gui': f_gui(args)
