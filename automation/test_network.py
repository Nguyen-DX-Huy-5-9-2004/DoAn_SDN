from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

from topology.botnet_topo import BotnetTopo

def run():

    topo = BotnetTopo()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1'),
        autoSetMacs=True
    )

    net.start()

    print("Testing connectivity...")
    net.pingAll()

    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()