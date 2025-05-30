#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import Controller
from mininet.cli import CLI
from functools import partial
from mininet.node import RemoteController
import os


# Topology: switches interconnected in diamond topology (3 parallel paths, no cross-links); 3 hosts on each side of the diamond

class MyTopo(Topo):
    "Single switch connected to n hosts."
    """ Note that you can control the numer (index) assigned to the ports in switches - see 
           https://mininet.org/api/classmininet_1_1net_1_1Mininet.html#ae01361739c8c8a4ab26a6bf12517d541
        So, for example, you can set:
           self.addLink(s1, s2, port1=10, port2=20, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
    """

    def __init__(self):
        Topo.__init__(self)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        self.addLink(h1, s1, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(h2, s1, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(h3, s1, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s2, bw=1, delay='200ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s3, bw=1, delay='50ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s1, s4, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s2, s5, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s3, s5, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s4, s5, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h4, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h5, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)
        self.addLink(s5, h6, bw=1, delay='10ms', loss=0, max_queue_size=1000, use_htb=True)


def perfTest():
    "Create network and run simple performance test"
    topo = MyTopo()
    # net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, controller=POXcontroller1)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink,
                  controller=partial(RemoteController, ip='0.0.0.0', port=6633))
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    h4, h5, h6 = net.get('h4', 'h5', 'h6')
    h1.setMAC("0:0:0:0:0:1")
    h2.setMAC("0:0:0:0:0:2")
    h3.setMAC("0:0:0:0:0:3")
    h4.setMAC("0:0:0:0:0:4")
    h5.setMAC("0:0:0:0:0:5")
    h6.setMAC("0:0:0:0:0:6")
    CLI(net)  # launch simple Mininet CLI terminal window
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    perfTest()
