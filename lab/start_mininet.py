from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from topology.research_topo import ResearchTopo

def run():

    topo = ResearchTopo()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        autoSetMacs=True
    )

    net.start()

    print("Testing connectivity")
    net.pingAll()

    CLI(net)

    net.stop()

if __name__ == "__main__":
    run()