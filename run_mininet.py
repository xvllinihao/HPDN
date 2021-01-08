from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink
from p4_mininet import P4Switch, P4Host, P4GrpcSwitch
#from p4runtime_switch import P4RuntimeSwitch
import random
import argparse
from time import sleep
import subprocess
import sys
import os
import psutil

parser = argparse.ArgumentParser(description='Mininet demo')
#parser.add_argument('--thrift-port', help='Thrift server port for table updates', type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch', type=int, action="store", default=2)
parser.add_argument('--p4-file', help='Path to P4 file', type=str, action="store", required=False)

args = parser.parse_args()

def get_all_virtual_interfaces():
    try:
        return subprocess.check_output(['ip addr | grep s.-eth. | cut -d\':\' -f2 | cut -d\'@\' -f1'], shell=True).split('\n')
    except subprocess.CalledProcessError as e:
        print_error('Cannot retrieve interfaces.')
        print_error(e)
        return ''

class SingleSwitchTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_path, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch1 = self.addSwitch('s0', sw_path = sw_path, json_path = json_path, grpc_port = 50051, device_id = 1)
        switch2 = self.addSwitch('s1', sw_path = sw_path, json_path = json_path, grpc_port = 50052, device_id = 2)
        switch3 = self.addSwitch('s2', sw_path = sw_path, json_path = json_path, grpc_port = 50053, device_id = 3)
        switch4 = self.addSwitch('s3', sw_path = sw_path, json_path = json_path, grpc_port = 50054, device_id = 4)

        # for h in xrange(n):
        #     host = self.addHost('h%d' % (h + 1), ip = "10.10.10.%d/16" % (h + 1), mac = '00:04:00:00:00:%02x' %h)
        #     self.addLink(host, switch1)

        # for h in xrange(n):
        host1 = self.addHost('h1', ip="10.10.10.00/16", mac='00:04:00:00:00:00')
        self.addLink(host1, switch1)
        host2 = self.addHost('h2', ip="10.10.10.01/16", mac='00:04:00:00:00:01')
        self.addLink(host2, switch1)
        host3 = self.addHost('h3', ip = "10.10.10.02/16", mac = '00:04:00:00:00:02')
        self.addLink(host3, switch2)
        host4 = self.addHost('h4', ip = "10.10.10.03/16", mac = '00:04:00:00:00:03')
        self.addLink(host4, switch2)
        host5 = self.addHost('h5', ip = "10.10.10.04/16", mac = '00:04:00:00:00:04')
        self.addLink(host5, switch3)
        host6 = self.addHost('h6', ip = "10.10.10.05/16", mac = '00:04:00:00:00:05')
        self.addLink(host6, switch3)

        host7 = self.addHost('h7', ip = "10.10.10.06/16", mac = '00:04:00:00:00:06')
        self.addLink(host7, switch4)
        host8 = self.addHost('h8', ip = "10.10.10.07/16", mac = '00:04:00:00:00:07')
        self.addLink(host8, switch4)

        self.addLink(switch1, switch2)
        self.addLink(switch3, switch2)
        # self.addLink(switch1, switch3)
        self.addLink(switch1, switch4)
        self.addLink(switch3, switch4)


        # server =  self.addHost('s1', ip = "10.10.3.3/16", mac = '00:00:01:01:01:01')
        # self.addLink('h1','h2')
        # self.addLink('h2','s1')
        # self.addLink('s1','h1')

        # self.addLink(server, switch)

def main():
    num_hosts = int(args.num_hosts)
    result = os.system("p4c --target bmv2 --arch v1model --p4runtime-files firmeware.p4info.txt "+ args.p4_file)
    p4_file = args.p4_file.split('/')[-1]
    json_file = p4_file.split('.')[0] + ".json"
    # json_file = "/home/hpdn/Downloads/p4-researching-master/src/fundamental/learning-switch/basic_tutorial_switch.json"

    topo = SingleSwitchTopo("simple_switch_grpc",
                            json_file,
                            num_hosts)
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4GrpcSwitch,
		  link = TCLink,
                  controller = None)
    net.start()

    interfaces = get_all_virtual_interfaces()
    for i in interfaces:
        if i!="":
            os.system("ip link set {} mtu 1600 > /dev/null".format(i))
	    os.system('ethtool --offload {} rx off  tx off > /dev/null'.format(i))


    net.staticArp()


    if result !=0:
        print "Error while compiling!"
        exit()

    switch_running="simple_switch_grpc" in (p.name() for p in psutil.process_iter())
    if switch_running==False:
        print "The switch didnt start correctly! Check the path to your P4 file!!"
        exit()

    print "Starting mininet!"

    CLI(net)

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
