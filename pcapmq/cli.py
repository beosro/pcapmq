# -*- coding: utf-8 -*-

"""Console script for pcapmq."""
import sys
import click

import pcap
import dpkt
import ipaddress


@click.command()
@click.option('--interface', default=None, help="Name of network interface, "
                                                "default use the first "
                                                "interface.")
@click.option('--filter', default="udp or arp", help="PCAP filter. Default is"
                                                " 'udp or arp'. Use 'ether "
                                                "src xx:xx:xx:xx:xx:xx' to "
                                                "track down particular device")
def main(interface, filter):
    """Console script for pcapmq."""
    sniffer = pcap.pcap(name=interface, promisc=True,
                        timeout_ms=50, immediate=True)
    sniffer.setfilter(filter)
    decode = {
        pcap.DLT_LOOP: dpkt.loopback.Loopback,
        pcap.DLT_NULL: dpkt.loopback.Loopback,
        pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
    }[sniffer.datalink()]
    
    click.echo('listening on %s: %s' % (sniffer.name, sniffer.filter))

    try:
        for ts, pkt in sniffer:
            d_pkt = decode(pkt)
            # if type(d_pkt.data) is dpkt.arp.ARP:
            #     src_ip = str(ipaddress.ip_address(d_pkt.data.spa))
            #     dest_ip = str(ipaddress.ip_address(d_pkt.data.tpa))
            #     if src_ip == '192.168.86.95' or dest_ip == '192.168.86.95':
            #         continue
            #     print("ARP: %s => %s" % (src_ip, dest_ip))

            # elif type(d_pkt.data) is dpkt.ip.IP:
            #     dest_ip = str(ipaddress.ip_address(d_pkt.data.dst))
            #     if dest_ip == '192.168.86.95':
            #         continue
            #     print("UDP => %s" % (dest_ip))
    
            msg = '%d %r' % (ts, d_pkt)
            click.echo(msg)

    except KeyboardInterrupt:
        pass

    finally:
        nrecv, ndrop, nifdrop = sniffer.stats()
        click.echo('\n%d packets received by filter' % nrecv)
        click.echo('%d packets dropped by kernel' % ndrop)

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
