import argparse, json
import network as networking

def network(args):

    mapper = networking.NetworkMapper()

    if args.host_discovery:

        result = mapper.discover(args.target, networking.Protocol.ARP if args.arp else 'icmp' if not args.arp and args.icmp else None)

        match args.output.lower():

            case 'json':
                print(json.dumps(result, indent=4))

            case _:

                for host, details in result.items():

                    output = f'Host: {host[0]}'
                    
                    for k, v in details.items():
                        output += f'\t{k.upper()}: {v}'

                    print(output)

def hashcrack(args):
    pass

if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='module')

    p_network = subparsers.add_parser('network', help='Enables the network module')
    p_network.add_argument('-hd', '--discovery', help='Enable host discovery scan', action='store_true')
    p_network.add_argument('-as', '--arp', help='Will use ARP scan for host discovery', action='store_true')
    p_network.add_argument('-id', '--icmp', help='Will use ICMP requests for host discovery', action='store_true')
    p_network.add_argument('--tcp', help='Port scanner will use TCP', action='store_true')
    p_network.add_argument('--udp', help='Port scanner will use UDP', action='store_true')
    p_network.add_argument('-o', '--output', help='Choose output format', default='')
    p_network.add_argument('target', help='The target CIDR / Host to scan', type=str)

    p_hashcrack = subparsers.add_parser('hashcrack', help='Enables the hashcrack module')
    p_hashcrack.add_argument('-f', '--hash', help='Path to the file containing the hashes')
    p_hashcrack.add_argument('-w', '--wordlist', help='Path to the wordlist')

    args = parser.parse_args()

    match args.module.lower():

        case 'network': network(args)
        case 'hashcrack': hashcrack(args)