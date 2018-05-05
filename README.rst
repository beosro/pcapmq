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
* (TODO) Publish message to MQTT when found particular packet on network


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

* Listening all UDP and ARP packet
```
sudo pcapmq --filter "udp or arp"
```

* Monitor specific device
```
sudo pcapmq --filter "ether src xx:xx:xx:xx:xx:xx"
```


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
