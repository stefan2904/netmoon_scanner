#! /usr/bin/env python

import scapy.config
import scapy.layers.l2
import scapy.route
import socket
import nmap
import math
import os

if os.geteuid() != 0:
    exit("You need to have root privileges to run the scanner ...")


def doPortscan(target_ip):
    nm = nmap.PortScanner()
    nm.scan(target_ip, '22-443')
    scan = nm[target_ip]

    for protocol in scan.all_protocols():

        open_ports = scan[protocol].keys()
        print '      found %d open %s ports: ' % (len(open_ports),
                                                  protocol)
        for port in open_ports:
            info = scan[protocol][port]
            print "        %4d: %s (%s %s): %s" % (port,
                                                   info['name'],
                                                   info['product'],
                                                   info['version'],
                                                   info['extrainfo'])


def ddn2cidr(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = 32 - int(round(math.log(0xFFFFFFFF - bytes_netmask, 2)))
    return "%s/%s" % (network, netmask)


def getActiveRoutes():
    '''
    returns routes of active network interface
    '''
    routes = filter(
        lambda x: x[3] == scapy.config.conf.iface,
        scapy.config.conf.route.routes)

    # filter out loopback/localhost and broadcast
    routes = filter(lambda x: x[0] != 0 and x[1] !=
                    0xFFFFFFFF and x[1] > 0, routes)

    # filter out zeroconf (?), 2851995648 => 169.254.0.0/16
    routes = filter(lambda x: x[0] != 2851995648, routes)

    return routes


def getHostsInNet(net):
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface,
                                            timeout=1, verbose=False)
    except:
        pass
    return ans


def getHostsInNetwork(network, netmask):
    net = ddn2cidr(network, netmask)
    return getHostsInNet(net)

if __name__ == '__main__':
    routes = getActiveRoutes()

    print '[*] found  %d networks via %s:' % (len(routes),
                                              scapy.config.conf.iface)

    for network, netmask, _, interface, address in routes:
        net = ddn2cidr(network, netmask)
        print '[*]  ', net

    for network, netmask, _, _, _ in routes:
        net = ddn2cidr(network, netmask)
        print '\n[*] scanning network', net, '...',

        for host in getHostsInNetwork(network, netmask):
            resp = host[1]
            hostname = socket.gethostbyaddr(resp.psrc)[0]
            print "\n    HOST %s == %-16s (%s)" % (resp.src,
                                                   resp.psrc, hostname)

            doPortscan(resp.psrc)