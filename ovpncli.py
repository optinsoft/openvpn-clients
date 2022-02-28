#!/bin/env python
# Copyright (c) 2022 Vitaly Yakovlev <vitaly@optinsoft.net>

from cProfile import run
from dotenv import load_dotenv
import argparse
import ipaddress
import json
import sys, os

def get_client_ip(client_network):
    ip_network = ipaddress.ip_network(client_network, False)      
    i = 0
    ip0 = ipaddress.ip_address(client_network.split('/')[0])
    for ip in ip_network.hosts():
        i += 1
        if (ip >= ip0 and i % 4 == 1):
            yield ip

def get_source_ip(source_networks):
    for source_network in source_networks:
        ip_network = ipaddress.ip_network(source_network, False)
        ip0 = ipaddress.ip_address(source_network.split('/')[0])
        for ip in ip_network.hosts():
            if (ip >= ip0):
                yield ip

def main():
    load_dotenv()

    script_name = "ovpncli.py"

    parser = argparse.ArgumentParser(description=script_name)

    parser.add_argument('--config', help='Path to the configuration file (JSON); you can either provide command line arguments to ' + script_name + ' or use the configuration file')

    parser.add_argument('-r', '--run', action="store_true", help='Run add-fw-rules or del-fw-rules')

    parser.add_argument('-p', '--permanent', action="store_true", help='Add or delete permanent forwarding rules')

    parser.add_argument('--client-index', type=int, default=1, help='First client index')
    parser.add_argument('--clients-count', type=int, help='Total number of clients that were created or removed')
    parser.add_argument('--clients-dir', help="Client files directory")
    parser.add_argument('--client-ip-network', help="Client ip network")
    parser.add_argument('--net-interface', help='Network interface')
    parser.add_argument('--source-networks', nargs='+', default=[], help='Source networks')

    parser.add_argument('action', choices=['create', 'clean', 'add-fw-rules', 'del-fw-rules'], help="Action: create or delete clients, add or delete forwarding rules")

    args = parser.parse_args()

    if (args.config):
        with open(args.config, 'rt') as f:
            t_args = argparse.Namespace()
            t_args.__dict__.update(json.load(f))
            args = parser.parse_args(namespace=t_args)

    action = args.action
    
    required_arg_names = ['clients_count', 'clients_dir']
    if (action == 'create'):
        required_arg_names.append('client_ip_network')
    if (action == 'add-fw-rules' or action == 'del-fw-rules'):
        required_arg_names.append('client_ip_network')
        required_arg_names.append('net_interface')
        required_arg_names.append('source_networks')

    vargs = vars(args)
    missed_args = ", ".join(filter(lambda name : vargs[name] is None, required_arg_names))

    if (missed_args):
        parser.print_usage()
        print("error: the following arguments are required: ", missed_args)
        sys.exit(0)

    client_index = args.client_index
    clients_count = args.clients_count
    clients_dir = args.clients_dir
    net_interface = args.net_interface
    client_ip = get_client_ip(args.client_ip_network)
    source_ip = get_source_ip(args.source_networks)

    permanent = ' --permanent' if args.permanent else '';

    for i in range(0, clients_count):
        client_name = "client" + str(i+client_index)
        client_file_path = os.path.join(clients_dir, client_name)
        if (action == 'create'):
            client_ip1 = client_ip.__next__()
            client_ip2 = client_ip1 + 1
            print("Creating client file: ", client_file_path)
            with open(client_file_path, "w") as f:
                f.write("ifconfig-push " + str(client_ip1) + " " + str(client_ip2))
        if (action == 'clean'):
            if (os.path.exists(client_file_path)):
                print("Removing file: ", client_file_path)
                os.remove(client_file_path)
        if (action == 'add-fw-rules'):
            client_ip1 = client_ip.__next__()
            cmd = "firewall-cmd --direct" + permanent + " --add-rule ipv4 nat POSTROUTING 0 -s %s -o %s -j SNAT --to-source %s" % (str(client_ip1), net_interface, source_ip.__next__())
            print(cmd)
            if (args.run):
                os.system(cmd)
        if (action == 'del-fw-rules'):
            client_ip1 = client_ip.__next__()
            cmd = "firewall-cmd --direct" + permanent + " --remove-rule ipv4 nat POSTROUTING 0 -s %s -o %s -j SNAT --to-source %s" % (str(client_ip1), net_interface, source_ip.__next__())
            print(cmd)
            if (args.run):
                os.system(cmd)

if __name__ == "__main__":
    main()
