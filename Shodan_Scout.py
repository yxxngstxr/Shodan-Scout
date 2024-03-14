import shodan
import argparse
import json
import os

def load_api_key():
    config_file = os.path.join(os.path.expanduser("~"), ".shodan_scout", "api_key.json")
    if os.path.isfile(config_file):
        with open(config_file, "r") as f:
            config = json.load(f)
        return config["api_key"]
    else:
        return None

def save_api_key(api_key):
    config_file = os.path.join(os.path.expanduser("~"), ".shodan_scout", "api_key.json")
    if not os.path.isdir(os.path.dirname(config_file)):
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
    with open(config_file, "w") as f:
        json.dump({"api_key": api_key}, f)

def search_shodan(query, num_results, country=None, port=None, os=None, ssl=None, banner=None, exploit=None, ip_range=None, limit=100, sort=None, output='txt', verbose=False, save=None):
    api = shodan.WebAPI(api_key)

    # Filter by IP range
    if ip_range:
        ip_range = tuple(map(int, ip_range.split('-')))
        results = list(filter(lambda r: ip_range[0] <= int(r['ip_str'].split('.')[0]) <= ip_range[1], api.search(query, page=1, per_page=limit, **filters)['matches']))
    else:
        results = api.search(query, page=1, per_page=limit, **filters)['matches']

    # Filter by since date
    if since:
        since = datetime.strptime(since, "%Y-%m-%d")
        results = list(filter(lambda r: datetime.strptime(r['last_update'], "%Y-%m-%dT%H:%M:%S.%fZ") >= since, results))

    # Sort results
    if sort:
        results = sorted(results, key=lambda r: r[sort], reverse=True)

    for result in results:
        host = api.host(result['ip_str'])
        print(f"{result['ip_str']} ({host['org']}):")
        print("\tOS: ", host.get('os', 'Unknown'))
        print("\tSSL: ", host.get('ssl', 'Unknown'))
        print("\tBanner: ", host.get('data', {}).get('product', 'Unknown'))

        # Search for known vulnerabilities and exploits related to this IP address
        if exploit:
            exploits = api.exploit(result['ip_str'])
            if exploits:
                print("\tVulnerabilities:")
                for exploit in exploits:
                    print(f"\t\t{exploit['title']} ({exploit['cve']})")

        # Save the search results to a file
        if save:
            if output == 'json':
                json.dump(result, save)
            elif output == 'csv':
                csv_writer = csv.DictWriter(save, fieldnames=result.keys())
                csv_writer.writerow(result)

def print_logo():
    logo = r"""
 (`-').-> (`-').->           _(`-')    (`-')  _ <-. (`-')_      (`-').->                                (`-')      
 ( OO)_   (OO )__      .->  ( (OO ).-> (OO ).-/    \( OO) )     ( OO)_   _             .->        .->   ( OO).->   
(_)--\_) ,--. ,'-'(`-')----. \    .'_  / ,---.  ,--./ ,--/     (_)--\_)  \-,-----.(`-')----. ,--.(,--.  /    '._   
/    _ / |  | |  |( OO).-.  ''`'-..__) | \ /`.\ |   \ |  |     /    _ /   |  .--./( OO).-.  '|  | |(`-')|'--...__) 
\_..`--. |  `-'  |( _) | |  ||  |  ' | '-'|_.' ||  . '|  |)    \_..`--.  /_) (`-')( _) | |  ||  | |(OO )`--.  .--' 
.-._)   \|  .-.  | \|  |)|  ||  |  / :(|  .-.  ||  |\    |     .-._)   \ ||  |OO ) \|  |)|  ||  | | |  \   |  |    
\       /|  | |  |  '  '-'  '|  '-'  / |  | |  ||  | \   |     \       /(_'  '--'\  '  '-'  '\  '-'(_ .'   |  |    
 `-----' `--' `--'   `-----' `------'  `--' `--'`--'  `--'      `-----'    `-----'   `-----'  `-----'      `--'    
"""
    print(logo)

def main():
    print_logo()
    parser = argparse.ArgumentParser(description="Explore the Shodan database and retrieve additional information about hosts.")
    parser.add_argument("query", help="The Shodan search query")
    parser.add_argument("--num-results", type=int, default=10, help="The number of results to retrieve (default: 10)")
    parser.add_argument("--country", help="The country code to filter results by (e.g., 'US')")
    parser.add_argument("--port", type=int, help="The port number to filter results by")
    parser.add_argument("--os", help="The operating system to filter results by (e.g., 'Windows')")
    parser.add_argument("--ssl", help="The SSL certificate information to filter results by (e.g., 'True')")
    parser.add_argument("--banner", help="The banner text to filter results by (e.g., 'Apache')")
    parser.add_argument("--exploit", action="store_true", help="Search for known vulnerabilities and exploits related to each IP address")
    parser.add_argument("--ip-range", "-i", help="Specify an IP address range to search within (e.g., '192.168.1.0-192.168.1.255')")
    parser.add_argument("--limit", "-l", type=int, default=100, help="Specify the maximum number of results to retrieve (default: 100)")
    parser.add_argument("--sort", "-s", choices=["ip", "org", "os"], default="ip", help="Specify the field to sort the search results by (default: ip)")
    parser.add_argument("--since", "-s", type=lambda d: datetime.strptime(d, "%Y-%m-%d"), help="Filter results by the date they were last seen by Shodan (e.g., '2022-01-01')")
    parser.add_argument("--output", "-o", choices=["json", "csv", "txt"], default="txt", help="Specify the output format for the search results (default: txt)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--save", "-s", type=argparse.FileType("w"), help="Save the search results to a file")

    args = parser.parse_args()

    api_key = load_api_key()
    if not api_key:
        api_key = input("Enter your Shodan API key: ")
        save_api_key(api_key)

    search_shodan(args.query, args.num_results, args.country, args.port, args.os, args.ssl, args.banner, args.exploit, args.ip_range, args.limit, args.sort, args.output, args.verbose, args.save)

if __name__ == "__main__":
    main()
