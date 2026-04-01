from mininet.net import Mininet
from mininet.node import RemoteController, Docker
from mininet.cli import CLI
from topology.research_topo import ResearchTopo

def run():

    topo = ResearchTopo()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        autoSetMacs=True
    )

    # 1. Thêm Docker web1 và mount thư mục code vào
    web1 = net.addDocker('web1', ip='10.0.0.10', dimage="python:3.9-slim", 
                         volumes=["/home/tgf/Documents/DoAn_SDN/services/my_web_app:/app"])

    # Link web1 to web server switch s6
    net.addLink(web1, net.get('s6'))

    net.start()

    # 2. Sau khi net.start(), ra lệnh cho web1 cài đặt thư viện và chạy server
    web1.cmd('cd /app && pip install -r requirements.txt')
    web1.cmd('cd /app && python manage.py migrate')
    web1.cmd('cd /app && echo "from django.contrib.auth.models import User; User.objects.create_superuser(\'admin\', \'admin@example.com\', \'admin123\')" | python manage.py shell')
    web1.cmd('python manage.py runserver 0.0.0.0:80 &')

    print("Testing connectivity")
    net.pingAll()

    CLI(net)

    net.stop()

if __name__ == "__main__":
    run()