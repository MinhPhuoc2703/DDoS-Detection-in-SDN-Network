from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink
import time
from mininet.log import setLogLevel, info


def create_network():
    # Create network with default controller
    net = Mininet(controller=RemoteController, link=TCLink)

    # Add controller
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Add SDN Router and ISP  Router
    r1 = net.addHost('r1')  # SDN Router
    r2 = net.addHost('r2')  # ISP  Router

    # Add OpenFlow Switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')  # Switch for hosts
    s2 = net.addSwitch('s2', protocols='OpenFlow13')  # Switch for server

    # Add hosts in SDN network
    h1 = net.addHost('h1', ip='192.168.1.2/24', defaultRoute='via 192.168.1.1')
    h2 = net.addHost('h2', ip='192.168.1.3/24', defaultRoute='via 192.168.1.1')
    h3 = net.addHost('h3', ip='192.168.1.4/24', defaultRoute='via 192.168.1.1')

    # Add server in separate network
    server = net.addHost('server', ip='192.168.2.2/24', defaultRoute='via 192.168.2.1')

    # Add attacker host
    attacker = net.addHost('attacker', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')

    # Create links
    net.addLink(r1, s1)  # Link SDN Router -> Switch for hosts
    net.addLink(r1, s2)  # Link SDN Router -> Switch for server
    net.addLink(r1, r2)  # Link SDN Router -> ISP  Router (Network 10.0.1.0)
    net.addLink(r2, attacker)  # Link ISP Router -> Attacker (Network 10.0.2.0)
    net.addLink(h1, s1)  # Host1 -> Switch for hosts
    net.addLink(h2, s1)  # Host2 -> Switch for hosts
    net.addLink(h3, s1)  # Host3 -> Switch for hosts
    net.addLink(server, s2)  # Server -> Switch for server

    # Start network
    net.start()

    # Configure SDN Router
    r1.cmd("ifconfig r1-eth0 192.168.1.1 netmask 255.255.255.0 up")  # Connect to Switch for hosts (192.168.1.0/24)
    r1.cmd("ifconfig r1-eth1 192.168.2.1 netmask 255.255.255.0 up")  # Connect to Switch for server (192.168.2.0/24)
    r1.cmd("ifconfig r1-eth2 10.0.1.2 netmask 255.255.255.0 up")  # Connect to r2 (Network 10.0.1.0)

    # Configure ISP Router
    r2.cmd("ifconfig r2-eth0 10.0.1.1 netmask 255.255.255.0 up")  # Connect to r1 (Network 10.0.1.0)
    r2.cmd("ifconfig r2-eth1 10.0.2.1 netmask 255.255.255.0 up")  # Connect to attacker (Network 10.0.2.0)
    

    # Enable IP forwarding on both routers
    r1.cmd("sysctl -w net.ipv4.ip_forward=1")
    r2.cmd("sysctl -w net.ipv4.ip_forward=1")

    # Add routes on SDN Router
    r1.cmd("ip route add 10.0.2.0/24 via 10.0.1.1 dev r1-eth2")  # Route to attacker's network
    r1.cmd('ip route add 0.0.0.0/0 via 10.0.1.2')

    # Add routes on ISP  Router
    r2.cmd("ip route add 192.168.1.0/24 via 10.0.1.2 dev r2-eth0")  # Route to SDN network
    r2.cmd("ip route add 192.168.2.0/24 via 10.0.1.2 dev r2-eth0")  # Route to server's network
    r2.cmd('ip route add 0.0.0.0/0 via 10.0.1.1')

    # Ensure all hosts can route to attacker via default gateway
    for host in [h1, h2, h3]:
        host.cmd("ip route add 10.0.2.0/24 via 192.168.1.1 dev {}-eth0".format(host.name))

    # Add route on server to attacker
    server.cmd("ip route add 10.0.2.0/24 via 192.168.2.1 dev server-eth0")

    # Add route on attacker to reach SDN network and server
    attacker.cmd("ip route add 192.168.1.0/24 via 10.0.2.1 dev attacker-eth0")
    attacker.cmd("ip route add 192.168.2.0/24 via 10.0.2.1 dev attacker-eth0")

    # Wait for routing tables to stabilize
    time.sleep(3)

    info("*** Starting web server\n")
    server.cmd("python3 -m http.server 80 &")
    info("*** Web server running at http://192.168.2.2\n")

    # Start CLI
    CLI(net)

    # Stop network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
