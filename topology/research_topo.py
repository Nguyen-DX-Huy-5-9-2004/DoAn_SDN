from mininet.topo import Topo


class ResearchTopo(Topo):

    def build(self):

        # --------------------------
        # CORE LAYER
        # --------------------------

        s1 = self.addSwitch('s1')

        # --------------------------
        # DISTRIBUTION LAYER
        # --------------------------

        s2 = self.addSwitch('s2')   # botnet distribution
        s3 = self.addSwitch('s3')   # client distribution

        # --------------------------
        # ACCESS LAYER
        # --------------------------

        s4 = self.addSwitch('s4')   # botnet access
        s5 = self.addSwitch('s5')   # datacenter
        s6 = self.addSwitch('s6')   # web server

        # Backbone

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s6)

        self.addLink(s2, s4)
        self.addLink(s3, s5)

        # --------------------------
        # DATACENTER SERVICES
        # --------------------------

        web = self.addHost(
            'h70',
            ip='10.0.0.100/24',
            mac='00:00:00:00:00:70'
        )

        dns = self.addHost(
            'h71',
            ip='10.0.0.101/24',
            mac='00:00:00:00:00:71'
        )

        api = self.addHost(
            'h72',
            ip='10.0.0.102/24',
            mac='00:00:00:00:00:72'
        )

        self.addLink(web, s6)
        self.addLink(dns, s5)
        self.addLink(api, s5)

        # --------------------------
        # SECURITY NODES
        # --------------------------

        ids = self.addHost(
            'h80',
            ip='10.0.0.200/24',
            mac='00:00:00:00:00:80'
        )

        honeypot = self.addHost(
            'h81',
            ip='10.0.0.201/24',
            mac='00:00:00:00:00:81'
        )

        monitor = self.addHost(
            'h82',
            ip='10.0.0.202/24',
            mac='00:00:00:00:00:82'
        )

        self.addLink(ids, s5)
        self.addLink(honeypot, s5)
        self.addLink(monitor, s6)

        # --------------------------
        # BOTNET
        # --------------------------

        for i in range(1, 21):

            ip = f"10.0.1.{i}/24"
            mac = f"00:00:00:00:01:{i:02x}"

            bot = self.addHost(
                f"h{i}",
                ip=ip,
                mac=mac
            )

            self.addLink(bot, s4)

        # --------------------------
        # NORMAL CLIENTS
        # --------------------------

        for i in range(60, 66):

            ip = f"10.0.2.{i}/24"
            mac = f"00:00:00:00:02:{i:02x}"

            client = self.addHost(
                f"h{i}",
                ip=ip,
                mac=mac
            )

            self.addLink(client, s3)


topos = {"research": ResearchTopo}