# Shodan Scout

Shodan Scout is a command-line tool for exploring the Shodan database and retrieving additional information about hosts. It allows users to search the Shodan database using advanced search options, filter the results by IP range, since date, and sort order, and save the results to a file in JSON or CSV format.

## Features

- A config file stored in a ".shodan_scout" folder in the user's home directory that saves the Shodan API key.
- Advanced search options that allow users to filter the search results by IP range, since date, and sort order.
- The ability to search for known vulnerabilities and exploits related to each IP address.
- Support for JSON, CSV, and plain text output formats.
- Verbose logging that can be enabled by the user.
- The ability to save the search results to a file in JSON or CSV format.

## Installation

To run Shodan Scout, you'll need Python installed along with the required dependencies listed in the requirements.txt file

Usage
To use Shodan Scout, you'll need a Shodan API key. You can obtain one by creating a Shodan account at https://account.shodan.io/.

When you run Shodan Scout for the first time, it will prompt you to enter your API key. It will save the API key to a config file in a ".shodan_scout" folder in your home directory. You won't need to enter your API key again unless you delete the config file.

To search the Shodan database, use the `--query` option followed by your search query:
```
shodan_scout --query "apache"
```
By default, Shodan Scout retrieves 10 results. You can change the number of results using the `--num-results option:`
```
shodan_scout --query "apache" --num-results 20
```
You can filter the results by IP range, country code, port number, operating system, SSL certificate information, and banner text using the following options:
```
shodan_scout --query "apache" --ip-range "192.168.1.0-192.168.1.255" --country "US" --port 80 --os "Windows" --ssl "True" --banner "Apache"
```
You can sort the results by IP address, organization name, or operating system using the `--sort` option:
```
shodan_scout --query "apache" --sort "ip"
```
You can filter the results by the date they were last seen by Shodan using the `--since` option:
```
shodan_scout --query "apache" --since "2022-01-01"
```
You can search for known vulnerabilities and exploits related to each IP address using the `--exploit` option:
```
shodan_scout --query "apache" --exploit
```
You can save the search results to a file in JSON or CSV format using the `--save` option:
```
shodan_scout --query "apache" --save results.json
```
```
shodan_scout --query "apache" --save results.csv
```
You can enable verbose logging using the `--verbose` option:
```
shodan_scout --query "apache" --verbose
```
Contributing
We welcome contributions to Shodan Scout. To contribute, please fork the repository and submit a pull request.
