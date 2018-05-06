================
Python PCAP2MQTT
================


.. image:: https://img.shields.io/pypi/v/pcapmq.svg
        :target: https://pypi.python.org/pypi/pcapmq

.. image:: https://img.shields.io/travis/rtfol/pcapmq.svg
        :target: https://travis-ci.org/rtfol/pcapmq

.. image:: https://readthedocs.org/projects/pcapmq/badge/?version=latest
        :target: https://pcapmq.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status

.. image:: https://pyup.io/repos/github/rtfol/pcapmq/shield.svg
     :target: https://pyup.io/repos/github/rtfol/pcapmq/
     :alt: Updates



Publish PCAP result to MQTT


* Free software: BSD license
* Documentation: https://pcapmq.readthedocs.io.


Features
--------

* Sniffer network packet
* Publish message to MQTT when found particular packet on network


Installation
--------

```
sudo apt install libpython3-dev libpcap-dev

pip install pcapmq
```


Configuration
--------

*(TODO)


Usage
--------

* Listening all UDP and ARP packet, send them to pcapmq/results topic
```
sudo pcapmq --filter "udp or arp" MQTT_BROKER_ADDRESS
```

* Send message to broker on 192.168.0.10 under topic devices/1/online, when found specific device's MAC address
```
sudo pcapmq --filter "ether src xx:xx:xx:xx:xx:xx" --topic devices/1/online 192.168.0.10
```
