# Tor IP Scanner

There are many projects out there that produce a list of Tor exit IPs, but this
one is the best. For us. Definitely. This is useful.

This scanner is better than all the all the rest because it does *everything*
to find as many IPs exits may use as possible:

- [ ] It records IPs of all relays found in Tor network state documents
  (regardless of whether they have the Exit flag or not) if they are willing to
exit to our IRC network. (Yes, you can configure yourself to have a very strict
exit policy such that you don't get the Exit flag but still allow a small
amount of exiting.)

- [ ] It builds circuits through these relays and connects to our IRC network
  to see if there are any other IPs that the relay ends up using when making
outbound connections. Again, yes this is possible.

## Tech

- Tor
- Stem
- Python 3
