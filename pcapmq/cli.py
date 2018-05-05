# -*- coding: utf-8 -*-

"""Console script for pcapmq."""
import sys
import click

import pcap
import dpkt


@click.command()
@click.option('--interface', default=None, help="Name of network interface, "
                                                "default use the first "
                                                "interface.")
def main(interface):
    """Console script for pcapmq."""
    sniffer = pcap.pcap(name=interface, promisc=True,
                        timeout_ms=50, immediate=True)
    sniffer.setfilter('arp')
    decode = {
        pcap.DLT_LOOP: dpkt.loopback.Loopback,
        pcap.DLT_NULL: dpkt.loopback.Loopback,
        pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
    }[sniffer.datalink()]
    
    click.echo('listening on %s: %s' % (sniffer.name, sniffer.filter))

    try:
        for ts, pkt in sniffer:
            msg = '%d %r' % (ts, decode(pkt))
            click.echo(msg)

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = sniffer.stats()
        click.echo('\n%d packets received by filter' % nrecv)
        click.echo('%d packets dropped by kernel' % ndrop)

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
