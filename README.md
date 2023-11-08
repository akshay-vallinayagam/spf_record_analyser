# spf_record_analyser

This tool allows you to compare SPF records of a domain with the domains listed in an input file. It highlights missing and extra IP's/mechanisms.

## Pre-requisites

- Python 3.10+
- dnspython (install with: pip install dnspython)

## Setup (One-time setup)

1. Clone this repository and navigate to the directory:
   ```
   git clone https://github.com/akshay-vallinayagam/spf_record_analyser.git && cd spf_record_analyzer
   ```

## Usage Instructions

To compare SPF records of a domain with the domains listed in an input file, use the following command:

```sh
python3 spf_record_analyzer.py [--debug] [--domain DOMAIN] [--file-path FILE_PATH]
```

Options:
- --help: 					   show this help message and exit
- --debug: 					   Enable debug logging (Optional)
- --domain DOMAIN: 			Input domain
- --file-path FILE_PATH: 	Path to the file with domain list

Example usage:

```sh
python3 spf_record_analyser.py --domain "example.com" --file-path "domains.txt" --debug
```

## About

The script requires a file containing domain entries as a dependency. The sample content of the input file is as follows:

```
_example1.com
example2.com
_spf.example.com
```

The tool will analyze SPF records, extract IP addresses, and compare them with the IPs from the input file. It will then print and return the missing/extra IPs.


## Future Enhancements

We have plans to expand the functionality of the spf_record_analyser to consider other SPF mechanisms, such as "ptr," "a," "exists," and more. Stay tuned for updates!

Thank you for using the spf_record_analyser.
