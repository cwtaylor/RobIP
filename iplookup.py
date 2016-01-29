#!/usr/bin/env python
"""This script performs basic enrichment on a given IP"""

from geoip import geolite2
from IPy import IP
from joblib import Parallel, delayed
from netaddr import IPSet, AddrFormatError
import csv
import dns.resolver
import json
import mmap
import os
import socket
import urllib


torcsv = 'Tor_ip_list_ALL.csv'
sfile = 'http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv'
SUBNET = 0
INPUTDICT = {}
SECTOR_CSV = 'sector.csv'
OUTFILE = 'IPLookup-output.csv'
CSVCOLS = ["ip-address", "asn", "as-name", "isp", "abuse-1", "abuse-2",
           "abuse-3", "domain", "reverse-dns", "type", "country", "lat",
           "long", "tor-node", "location", "abuse-contacts"]


def identify(var):
    result = ""
    with open(SECTOR_CSV) as f:
        root = csv.reader(f)
        for i in root:
            if i[0] in var:
                result = i[1]
    return result


def lookup(value):
    """Performs a dns request on the given value"""
    try:
        answers = dns.resolver.query(value, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                value = txt_string.replace(" | ", "|")
                value = value.replace(" |", "|").split("|")
    except:
        value = []
    return value


def flookup(value, fname, sfile):
    """Looks up a value in a file"""
    try:
        fhandle = open(fname)
    except IOError:
        sourceFile = urllib.URLopener()
        sourceFile.retrieve(
            sfile,
            fname)
        fhandle = open(fname)
    search = mmap.mmap(fhandle.fileno(), 0, access=mmap.ACCESS_READ)
    if search.find(value) != -1:
        return 'true'
    else:
        return 'false'


def iprange(sample, sub):
    """Identifies if the given ip address is in the previous range"""
    if sub is not 0:
        try:
            ipset = IPSet([sub])
            if sample in ipset:
                return True
        except AddrFormatError:
            return False
    else:
        return False


def mainlookup(var):
    """Wraps the main lookup and generated the dictionary"""
    global SUBNET
    global INPUTDICT
    var = ''.join(var.split())
    if IP(var).iptype() != 'PRIVATE' and IP(var).version() == 4:
        if iprange(var, SUBNET) is True:
            print
        elif INPUTDICT.get("ip-address") == var:
            print
        else:
            try:
                socket.inet_aton(var)
            except socket.error:
                var = socket.gethostbyname(var)
            contactlist = []
            rvar = '.'.join(reversed(str(var).split(".")))

            origin = lookup(rvar + '.origin.asn.shadowserver.org')
            try:
                SUBNET = origin[1]
            except:
                pass

            try:
                contact = lookup(rvar + '.abuse-contacts.abusix.org')
                contactlist = str(contact[0]).split(",")
            except:
                contactlist = []

            contactlist.extend(["-"] * (4 - len(contactlist)))
            try:
                addr = reversename.from_address(var)
                rdns = str(resolver.query(addr, "PTR")[0])
            except:
                rdns = ""

            match = geolite2.lookup(var)
            if match is None or match.location is None:
                country = ''
                location = ["", ""]
            else:
                country = match.country
                location = match.location

            tor = flookup(var, torcsv, sfile)
            try:
                category = identify(origin[4])
                if category == "":
                    category = identify(contactList[0])
            except:
                category = ''
            origin.extend(["-"] * (6 - len(origin)))
            INPUTDICT = {
                'abuse-1': contactlist[0],
                'abuse-2': contactlist[1],
                'abuse-3': contactlist[2],
                'as-name': origin[2],
                'asn': origin[0],
                'country': country,
                'descr': origin[5],
                'domain': origin[4],
                'ip-address': var,
                'lat': location[0],
                'long': location[1],
                'reverse-dns': rdns,
                'tor-node': tor,
                'sector': category,
            }
    else:
        INPUTDICT = {
            'abuse-1': "", 'abuse-2': "", 'abuse-3': "", 'as-name': "",
            'asn': "", 'country': "", 'descr': "", 'domain': "",
            'domain-count': "", 'ip-address': var, 'lat': "", 'long': "",
            'reverse-dns': "", 'tor-node': "", 'sector': "",
        }
    INPUTDICT['ip-address'] = var

    out = json.dumps(
        INPUTDICT,
        indent=4,
        sort_keys=True,
        ensure_ascii=False)
    csvout(INPUTDICT)
    print(out)


def batch(inputfile):
    """Handles batch lookups using file based input"""
    if os.path.isfile(OUTFILE):
        os.remove(OUTFILE)

    with open(inputfile) as fhandle:
        Parallel(n_jobs=100, verbose=51)(delayed(mainlookup)(i.rstrip('\n'))
                                         for i in fhandle)


def single(lookupvar):
    """Caries out a single IP lookup"""
    result = mainlookup(lookupvar)
    return result


def csvout(inputdict):
    """Generates a CSV file from the output inputdict"""
    fhandle = open(OUTFILE, "a")
    try:
        writer = csv.writer(fhandle, quoting=csv.QUOTE_ALL)
        writer.writerow((
            inputdict['ip-address'],
            inputdict['asn'],
            inputdict['as-name'],
            inputdict['descr'],
            inputdict['abuse-1'],
            inputdict['abuse-2'],
            inputdict['abuse-3'],
            inputdict['domain'],
            inputdict['reverse-dns'],
            inputdict['sector'],
            inputdict['country'],
            inputdict['lat'],
            inputdict['long'],
            inputdict['tor-node']))
    finally:
        fhandle.close()


def main():
    import argparse
    PARSER = argparse.ArgumentParser()
    PARSER.add_argument("-t",
                        choices=('single', 'batch'),
                        required="false",
                        metavar="request-type",
                        help="Either single or batch request")
    PARSER.add_argument("-v",
                        required="false",
                        metavar="value",
                        help="The value of the request")
    ARGS = PARSER.parse_args()

    if ARGS.t == "single":
        single(ARGS.v)
    elif ARGS.t == "batch":
        batch(ARGS.v)
    else:
        PARSER.print_help()

if __name__ == "__main__":
    main()
