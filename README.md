# Tor IP Scanner

There are many projects out there that produce a list of Tor exit IPs, but this
one is the best. For us. Definitely. This is useful.

This scanner is better than all the all the rest because it does *everything*
to find as many IPs exits may use as possible:

- It records ORPort IPs (both v4 and v6) from the server descriptors of all
  relays that can exit to OFTC infrastructure, regardless of whether or not
they have the Exit flag.

- Through the relays that can connect to OFTC's user-facing ircds, we build
  circuits and connect to an ircd in order to get it to report to us what
hostname/IP we are coming from. If we get a hostname, we lookup its A and AAAA
records.

- For all relays that can connect to OFTC infrastructure, we see if the IPs in
  their descriptors have rDNS entries, and if so, we lookup A and AAAA records.

To be explicit: "OFTC infrastructure" includes our user-facing ircds *and* our
web irc client. For relays that can only exit to our web IRC client, we only
check their descriptors and do DNS queries.

## Tech

- Tor
- Stem
- Python 3.7

## Install

This will install Tor IP Scanner and its dependencies into a virtualenv
suitable for development work.

    $ cd to/this/directory
    $ python3 -m venv venv
    $ . venv/bin/activate
    $ pip install -U pip
    $ pip install -e .[dev]

## Using

Start the scanner with `toripscanner scan`. It runs in the foreground and stays
running forever, periodically scanning new relays.

Periodically run `toripscanner parse data/results/*` to parse the scanner's
results into a plaintext list of IPv4/6 addresses. The command only uses
"recent" results even if the input files it reads contain old results.
