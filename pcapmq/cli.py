# -*- coding: utf-8 -*-

"""Console script for pcapmq."""
import sys
import click

import pcap
import dpkt
import ipaddress
import paho.mqtt.client as mqtt


@click.command()
@click.option('--interface', default=None, help="Name of network interface, "
                                                "default use the first "
                                                "interface.")
@click.option('--filter', default="udp or arp", help="PCAP filter. Default is"
                                                " 'udp or arp'. Use 'ether "
                                                "src xx:xx:xx:xx:xx:xx' to "
                                                "track down particular device")
@click.option('--topic', default="pcapmq/result", help="MQTT topic. Default "
                                                       " is pcapmq/result")
@click.option('--port', default=1883, help="MQTT broker port, default is 1883")
@click.argument('mqtt-broker')
def main(interface, filter, topic, port, mqtt_broker):
    """Send PCAP result to MQTT broker"""
    client = mqtt.Client()
    client.connect(mqtt_broker, port)
    click.echo("connected to MQTT broker on %s:%s" % (mqtt_broker, port))

    sniffer = pcap.pcap(name=interface, promisc=True,
                        timeout_ms=50, immediate=True)
    sniffer.setfilter(filter)
    decode = {
        pcap.DLT_LOOP: dpkt.loopback.Loopback,
        pcap.DLT_NULL: dpkt.loopback.Loopback,
        pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
    }[sniffer.datalink()]
    
    click.echo("listening on %s: %s" % (sniffer.name, sniffer.filter))

    try:
        for timestamp, packet in sniffer:
            decoded_packet = decode(packet)
            message = '%d %r' % (timestamp, decoded_packet)
            client.publish(topic, message)
            click.echo(message)

    except KeyboardInterrupt:
        pass

    finally:
        received, dropped, dropped_by_interface = sniffer.stats()
        click.echo("\n%d packets received by filter" % received)
        click.echo("%d packets dropped by kernel" % dropped)
        click.echo("%d packets dropped by interface" %
                   dropped_by_interface)
        client.disconnect()
        click.echo("disconnected from MQTT broker")

    return 0


if __name__ == "__main__":
    sys.exit(main())  # pylint: disable=no-value-for-parameter
