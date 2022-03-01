#!/bin/env python
# Copyright (c) 2022 Vitaly Yakovlev <vitaly@optinsoft.net>

from cProfile import run
from dotenv import load_dotenv
import argparse
import ipaddress
import json
import sys, os
import paramiko

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

def os_exec_command_decorator(pre_cmd: str = "", run: bool = False):
    if run:
        def run_wrapper(cmd: str):
            exec_cmd = pre_cmd + cmd
            print(exec_cmd)
            os.system(exec_cmd)
        return run_wrapper
    def dont_run_wrapper(cmd: str):
        exec_cmd = pre_cmd + cmd
        print(exec_cmd)
    return dont_run_wrapper

def os_file_exists():
    def wrapper(file_path: str):
        return os.path.exists(file_path)
    return wrapper

def ssh_exec_command_decorator(ssh, pre_cmd: str = "", run: bool = False):
    if run:
        def run_wrapper(cmd: str):
            exec_cmd = pre_cmd + cmd
            print(exec_cmd)
            stdin, stdout, stderr = ssh.exec_command(exec_cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()
            if out:
                sys.stdout.write(out)
            if err:
                sys.stderr.write(err)
        return run_wrapper
    def dont_run_wrapper(cmd: str):
        exec_cmd = pre_cmd + cmd
        print(exec_cmd)
    return dont_run_wrapper

def ssh_file_exists(sftp):
    def wrapper(file_path: str):
        try:
            sftp.stat(file_path)
            return True
        except IOError:
            return False
    return wrapper

def main():
    load_dotenv()

    script_name = "ovpncli.py"

    parser = argparse.ArgumentParser(description=script_name)

    parser.add_argument('--config', help='Path to the configuration file (JSON); you can either provide command line arguments to ' + script_name + ' or use the configuration file')

    parser.add_argument('-r', '--run', action="store_true", help='Run add-fw-rules or del-fw-rules')

    parser.add_argument('-p', '--permanent', action="store_true", help='Add or delete permanent forwarding rules')

    parser.add_argument('-k', '--keys', action="store_true", help="Create or delete (clean) easy-rsay keys")

    parser.add_argument('--client-index', type=int, default=1, help='First client index')
    parser.add_argument('--clients-count', type=int, help='Total number of clients that were created or removed')
    parser.add_argument('--clients-dir', help="Client files directory")
    parser.add_argument('--client-ip-network', help="Client ip network")
    parser.add_argument('--easy-rsa-dir', help="Easy-rsa directory")
    parser.add_argument('--easy-rsa-keys-dir', help="Easy-rsa keys directory")
    parser.add_argument('--use-ssh', default=False, type=bool, help="Use SSH")
    parser.add_argument('--ssh-host', help='SSH host')
    parser.add_argument('--ssh-port', default=22, type=int, help='SSH port')
    parser.add_argument('--ssh-user', help='SSH user')
    parser.add_argument('--ssh-keyfile', help='SSH private key file')    
    parser.add_argument('--net-interface', help='Network interface')
    parser.add_argument('--source-networks', nargs='+', default=[], help='Source networks')

    parser.add_argument('action', choices=['create', 'clean', 'add-fw-rules', 'del-fw-rules'], help="Action: create or delete (clean) clients, add or delete forwarding rules")

    args = parser.parse_args()

    if (args.config):
        with open(args.config, 'rt') as f:
            t_args = argparse.Namespace()
            t_args.__dict__.update(json.load(f))
            args = parser.parse_args(namespace=t_args)

    action = args.action
    
    required_arg_names = ['clients_count']
    if (action == 'create'): 
        # or action == 'clean'):
        if (args.keys):
            required_arg_names.append('easy_rsa_dir')
            required_arg_names.append('easy_rsa_keys_dir')
            action = action+'_keys'
        else:
            required_arg_names.append('clients_dir')
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
    net_interface = args.net_interface
    client_ip = get_client_ip(args.client_ip_network)
    source_ip = get_source_ip(args.source_networks)

    permanent = ' --permanent' if args.permanent else ''

    if args.use_ssh:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_key = paramiko.RSAKey.from_private_key_file(args.ssh_keyfile)
        ssh.connect(hostname=args.ssh_host, port=args.ssh_port, username=args.ssh_username, pkey=ssh_key)
        sftp = ssh.open_sftp()

    if (action == 'create_keys'):
        pre_cmd = "cd " + args.easy_rsa_dir + " ; source ./vars; "
    else:
        pre_cmd = ""

    exec_command = ssh_exec_command_decorator(ssh, pre_cmd, args.run) if args.use_ssh else os_exec_command_decorator(pre_cmd, args.run)

    file_exists = ssh_file_exists(sftp) if args.use_ssh else os_file_exists()

    for i in range(0, clients_count):
        client_name = "client" + str(i+client_index)
        if (action == 'create'):
            client_ip1 = client_ip.__next__()
            client_ip2 = client_ip1 + 1
            client_file_path = os.path.join(args.clients_dir, client_name)
            print("Creating client file: ", client_file_path)
            with open(client_file_path, "w") as f:
                f.write("ifconfig-push " + str(client_ip1) + " " + str(client_ip2))
        if (action == 'clean'):
            client_file_path = os.path.join(args.clients_dir, client_name)
            if (os.path.exists(client_file_path)):
                print("Removing client file: ", client_file_path)
                os.remove(client_file_path)
        if (action == 'create_keys'):
            key_file_name = client_name + ".key"
            key_file_path = os.path.join(args.easy_rsa_keys_dir, key_file_name)
            if (file_exists(key_file_path)):
                print('Key file already exists: ', key_file_path)
            else:
                # print('Key file does not exist: ', key_file_path)
                print("Creating key file: ", key_file_name)
                cmd = "KEY_CN=" + client_name + "; ./build-key --batch " + client_name
                exec_command(cmd)
            # crt_file_name = client_name + ".crt"
            # crt_file_path = os.path.join(args.easy_rsa_keys_dir, crt_file_name)
            # if (file_exists(crt_file_path)):
            #     print('Certificate file already exists: ', crt_file_path)
            # else:
            #     print('Certificate file does not exist: ', crt_file_path)
#        if (action == 'clean_keys'):
#            key_file_name = client_name + ".key"
#            key_file_path = os.path.join(args.easy_rsa_keys_dir, key_file_name)
#            if (file_exists(key_file_path)):
#                print("Removing key file: ", key_file_path)
#                cmd = "rm " + key_file_path
#                exec_command(cmd)
#            crt_file_name = client_name + ".crt"
#            crt_file_path = os.path.join(args.easy_rsa_keys_dir, crt_file_name)
#            if (file_exists(crt_file_path)):
#                print("Removing certificate file: ", crt_file_path)
#                cmd = "rm " + crt_file_path
#                exec_command(cmd)
#            csr_file_name = client_name + ".csr"
#            csr_file_path = os.path.join(args.easy_rsa_keys_dir, csr_file_name)
#            if (file_exists(csr_file_path)):
#                print("Removing csr file: ", csr_file_path)
#                cmd = "rm " + csr_file_path
#                exec_command(cmd)
        if (action == 'add-fw-rules'):
            client_ip1 = client_ip.__next__()
            cmd = "firewall-cmd --direct" + permanent + " --add-rule ipv4 nat POSTROUTING 0 -s %s -o %s -j SNAT --to-source %s" % (str(client_ip1), net_interface, source_ip.__next__())
            exec_command(cmd)
        if (action == 'del-fw-rules'):
            client_ip1 = client_ip.__next__()
            cmd = "firewall-cmd --direct" + permanent + " --remove-rule ipv4 nat POSTROUTING 0 -s %s -o %s -j SNAT --to-source %s" % (str(client_ip1), net_interface, source_ip.__next__())
            exec_command(cmd)

if __name__ == "__main__":
    main()
