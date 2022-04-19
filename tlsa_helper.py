#!/usr/bin/env python3
# coding=utf-8

"""
+-----------------------------------------------------------------------------+
|                                 TLSA Helper                                 |
+-----------------------------------------------------------------------------+
This little program will help you create a TLSA record from the given
public key certificate file. It supports all combinations of usage, selector
and matching type as specified in RFC 6698, specifically:

    2.1.1.  The Certificate Usage Field
        Usage:  0: PKIX-TA: CA Constraint,
                1: PKIX-EE: Service Certificate Constraint,
                2: DANE-TA: Trust Anchor Assertion,
                3: DANE-EE: Domain Issued Certificate.
    2.1.2.  The Selector Field
        Selector:   0: Full certificate,
                    1: Subject public key.
    2.1.3.  The Matching Type Field
        Matching Type:  0: Full selector,
                        1: SHA-256 hash,
                        2: SHA-512 hash.
+-----------------------------------------------------------------------------+
Usage as follows:
tlsa_helper.py -c <certificate file> -u <usage> -s <selector> -m <matching type>

Example:
tlsa_helper.py --certfile my_certificate.pem --usage 3 --selector 0 --matchtype 2
+-----------------------------------------------------------------------------+
Author:         Simon
Latest change:  2022-04-08
+-----------------------------------------------------------------------------+
"""

import sys
import hashlib
import datetime
import argparse
import M2Crypto


def hex_dump(inputstring, separator=''):
    """Return a hexadecimal representation of the given string."""
    hexlist = ["%02x" % ord(x) for x in inputstring]
    return separator.join(hexlist)


def compute_hash(function, string):
    """Compute hash of string using given hash function."""
    hash = function()
    hash.update(string)
    return hash.hexdigest()


def certfile_to_certobj(filename):
    """Convert cert file to M2Crypto X509 object, this will work in most cases,
    with both ASCII (PEM/PKCS#7) and binary formatted files (DER/PKCS#12)."""
    return M2Crypto.X509.load_cert_string(open(filename).read())


def get_certdata(cert_obj, selector):
    """Given selector, return certificate data in binary (DER) form."""
    if selector == 0:
        cert_data = cert_obj.as_der()
    elif selector == 1:
        cert_data = cert_obj.get_pubkey().as_der()
    else:
        raise ValueError("Selector type %d not recognized" % selector)
    return cert_data


def get_hexdata(cert_data, match_type):
    """Given matchtype, return hex of certdata or its hash."""
    if match_type == 0:
        hex_data = hex_dump(cert_data)
    elif match_type == 1:
        hex_data = compute_hash(hashlib.sha256, cert_data)
    elif match_type == 2:
        hex_data = compute_hash(hashlib.sha512, cert_data)
    else:
        raise ValueError("Matchtype %d not recognized" % match_type)
    return hex_data


def check_cert_expiration(expiration):
    """Checks the certificates expiration date and warns if < 90."""
    today = datetime.datetime.now().replace(tzinfo=None)
    delta = today - expiration.replace(tzinfo=None)

    if delta.days > -90 and delta.days < 0:
        print(
            "\033[91m \tWarning: This certificate expires in less than 90 days.\x1b[0m")
    elif delta.days > 0:
        print("\033[91m \tWarning: This certificate has expired.\x1b[0m")


def tlsa_record_information():
    """Display some record information."""
    print("\nDNS Record information:")
    print("\tNote that the full DNS resource record shows:")
    print("\tPort:\t\t This can be any port (example: 443).")
    print("\tProtocol:\t This can be tcp, udp or sctp.")
    print("\tDomain:\t\t The domain (example: example.org).")
    print("\tThe above would result in the full TLSA DNS resource record:\n")
    print("_443._tcp.example.org. IN TLSA %d %d %d %s" %
          (args.usage, args.selector, args.matchtype, hexdata))
    print("\nTip: Use the '--generate yes' option to generate a full DNS resource record.")


def generate_dns_record(usage, sel, matchtype, hexdata):
    """Generates a full DNS resource record."""
    print("\nEnter the following information to create a DNS resource record:")
    port = input("Enter port:")
    protocol = input("Enter protocol:")
    domain = input("Enter domain:")
    print("\nThis is your DNS resource record:")
    print("_%s._%s.%s." % (port, protocol, domain),
          "IN TLSA %d %d %d %s" % (usage, sel, matchtype, hexdata))


def super_cool_banner():
    """This program will probably not even work without this."""
    print("\n" * 50)
    print("""\x1b['\33[31m
    ████████╗██╗     ███████╗ █████╗     ██╗  ██╗███████╗██╗     ██████╗ ███████╗██████╗
    ╚══██╔══╝██║     ██╔════╝██╔══██╗    ██║  ██║██╔════╝██║     ██╔══██╗██╔════╝██╔══██╗
       ██║   ██║     ███████╗███████║    ███████║█████╗  ██║     ██████╔╝█████╗  ██████╔╝
       ██║   ██║     ╚════██║██╔══██║    ██╔══██║██╔══╝  ██║     ██╔═══╝ ██╔══╝  ██╔══██╗
       ██║   ███████╗███████║██║  ██║    ██║  ██║███████╗███████╗██║     ███████╗██║  ██║
       ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝
    \x1b[0m""")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--certfile",
                        help="A certificate file in PEM format.")
    parser.add_argument("-u", "--usage", type=int,
                        dest="usage", default=3,
                        help="The certificate usage field (0, 1, 2 or 3).")
    parser.add_argument("-s", "--selector", type=int,
                        dest="selector", default=1,
                        help="The selector field (0 or 1).")
    parser.add_argument("-m", "--matchtype", type=int,
                        dest="matchtype", default=1,
                        help="The matching type field (0, 1 or 2).")
    parser.add_argument("-g", "--generate",
                        dest="generate", default="no",
                        help="Get help to generate full record.")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    super_cool_banner()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    certobj = certfile_to_certobj(args.certfile)
    certdata = get_certdata(certobj, args.selector)
    hexdata = get_hexdata(certdata, args.matchtype)

    print("Certificate information:")
    print("\tSubject: %s" % certobj.get_subject().as_text())
    print("\tIssuer : %s" % certobj.get_issuer().as_text())
    print("\tSerial : %x" % certobj.get_serial_number())
    try:
        san = certobj.get_ext('subjectAltName')
        print("\tSubject Alternative Name(s): %s" % san.get_value())
    except LookupError:
        pass

    validity_not_before = certobj.get_not_before().get_datetime()
    validity_not_after = certobj.get_not_after().get_datetime()
    print("\tCertificate validity from (not before):  %s %s" %
          (validity_not_before, validity_not_before.tzname()))
    print("\tCertificate validity to (not after): %s %s" %
          (validity_not_after, validity_not_after.tzname()))
    check_cert_expiration(validity_not_after)

    print("\nGenerated TLSA Record:")
    print("\033[0;37;41m%d %d %d %s" %
          (args.usage, args.selector, args.matchtype, hexdata), "\x1b[0m")

    tlsa_record_information()

    if args.generate == "yes":
        generate_dns_record(args.usage, args.selector, args.matchtype, hexdata)
