# RobIP
[![Code Health](https://landscape.io/github/cwtaylor/RobIP/master/landscape.svg?style=flat)](https://landscape.io/github/cwtaylor/RobIP/master)

The RobIP script takes either a single or file of IP addresses and uses various enrichment providers to return useful information regarding an IP address.

Shadowserver is the main source of information for the enrichment process. This process uses their IP-BGP service to return information.

Currently the following is returned as a JSON blob:

```json
{
    "abuse-1": "abuse@example.org",
    "abuse-2": "abuse2@example.org",
    "abuse-3": "abuse3@example.org",
    "as-name": "EXAMPLE",
    "asn": "1234",
    "country": "GB",
    "descr": "Example ISP",
    "domain": "example.org",
    "ip-address": "192.168.1.1",
    "lat": 50.7967,
    "long": -1.0833,
    "reverse-dns": "pc.example.org",
    "tor-node": "false",
    "sector": "Example"
}
```
Additionally a CSV file is generated from the output.


## Dependencies
The script currently only works on Python2.x and not Python3.x. The following python libraries are required and can be installed with pip.
- dnspython
- joblib


### Installation on Ubuntu 15.10 (and older)
```
sudo pip install -r requirements.txt
```

## License
See the [LICENSE](LICENSE) file for license rights and limitations (GPLv3).
