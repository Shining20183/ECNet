#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/11/14 10:08        1.0      给定攻击者的ip，把和攻击相关的数据包都过滤出来，存储到一个pcap文件中，然后将数据包的16进制存储到csv文件中
'''

import os
import subprocess
import csv
import dpkt
import socket
import traceback

type2path = {
    'ftp_bruteforce': [
        '/home/new_data/ori_data/0214_pcap_30min_combine/4_0214_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0214_pcap_30min_combine/5_0214_30min_11_00-11_30_mixed.pcap',
        '/home/new_data/ori_data/0214_pcap_30min_combine/6_0214_30min_11_30-12_00_mixed.pcap',
        '/home/new_data/ori_data/0214_pcap_30min_combine/7_0214_30min_12_00-12_30_mixed.pcap'
    ],
    'ssh_bruteforce': [
        '/home/new_data/ori_data/0214_pcap_30min_combine/11_0214_30min_14_00-14_30_mixed.pcap',
        '/home/new_data/ori_data/0214_pcap_30min_combine/12_0214_30min_14_30-15_00_mixed.pcap',
        '/home/new_data/ori_data/0214_pcap_30min_combine/13_0214_30min_15_00-15_30_mixed.pcap'],
    'dos_goldeneye': [
        '/home/new_data/ori_data/0215_pcap_30min_combine/1_0215_30min_9_00-9_30_mixed.pcap',
        '/home/new_data/ori_data/0215_pcap_30min_combine/2_0215_30min_9_30-10_00_mixed.pcap',
        '/home/new_data/ori_data/0215_pcap_30min_combine/3_0215_30min_10_00-10_30_mixed.pcap'],
    'dos_slowloris': [
        '/home/new_data/ori_data/0215_pcap_30min_combine/5_0215_30min_11_00-11_30_mixed.pcap',
        '/home/new_data/ori_data/0215_pcap_30min_combine/6_0215_30min_11_30-12_00_mixed.pcap'],

    'dos_slowhttp': [
        '/home/new_data/ori_data/0216_pcap_30min_combine/3_0216_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0216_pcap_30min_combine/4_0216_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0216_pcap_30min_combine/5_0216_30min_11_00-11_30_mixed.pcap'],
    'dos_hulk': [
        '/home/new_data/ori_data/0216_pcap_30min_combine/10_0216_30min_13_30-14_00_mixed.pcap',
        '/home/new_data/ori_data/0216_pcap_30min_combine/11_0216_30min_14_00-14_30_mixed.pcap'],

    'ddos_loic_http': [
        '/home/new_data/ori_data/0220_pcap_30min_combine/3_0220_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0220_pcap_30min_combine/4_0220_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0220_pcap_30min_combine/5_0220_30min_11_00-11_30_mixed.pcap'],
    'ddos_loic_udp': [
        '/home/new_data/ori_data/0220_pcap_30min_combine/9_0215_30min_13_00-13_30_mixed.pcap'],
    'bruteforce_web': [
        '/home/new_data/ori_data/0222_pcap_30min_combine/3_0222_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0222_pcap_30min_combine/4_0222_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0222_pcap_30min_combine/5_0222_30min_11_00-11_30_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/3_0223_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/4_0223_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/5_0223_30min_11_00-11_30_mixed.pcap'
    ],
    'bruteforce_xss': [
        '/home/new_data/ori_data/0222_pcap_30min_combine/10_0222_30min_13_30-14_00_mixed.pcap',
        '/home/new_data/ori_data/0222_pcap_30min_combine/11_0222_30min_14_00-14_30_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/9_0223_30min_13_00-13_30_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/10_0223_30min_13_30-14_00_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/11_0223_30min_14_00-14_30_mixed.pcap'],
    'sql_injection': [
        '/home/new_data/ori_data/0222_pcap_30min_combine/15_0222_30min_16_00-16_30_mixed.pcap',
        '/home/new_data/ori_data/0223_pcap_30min_combine/13_0223_30min_15_00-15_30_mixed.pcap'],
    'infiltration': [
        '/home/new_data/ori_data/0228_pcap_30min_combine/4_0228_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/5_0228_30min_11_00-11_30_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/6_0228_30min_11_30-12_00_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/7_0228_30min_12_00-12_30_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/10_0228_30min_13_30-14_00_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/11_0228_30min_14_00-14_30_mixed.pcap',
        '/home/new_data/ori_data/0228_pcap_30min_combine/12_0228_30min_14_30-15_00_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/2_0301_30min_9_30-10_00_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/3_0301_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/4_0301_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/11_0301_30min_14_00-14_30_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/12_0301_30min_14_30-15_00_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/13_0301_30min_15_00-15_30_mixed.pcap',
        '/home/new_data/ori_data/0301_pcap_30min_combine/14_0301_30min_15_30-16_00_mixed.pcap'
    ],
    'bot': [
        '/home/new_data/ori_data/0302_pcap_30min_combine/3_0302_30min_10_00-10_30_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/4_0302_30min_10_30-11_00_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/5_0302_30min_11_00-11_30_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/6_0302_30min_11_30-12_00_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/11_0302_30min_14_00-14_30_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/12_0302_30min_14_30-15_00_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/13_0302_30min_15_00-15_30_mixed.pcap',
        '/home/new_data/ori_data/0302_pcap_30min_combine/14_0302_30min_15_30-16_00_mixed.pcap'
    ]
}


type2ip = {
    'ftp_bruteforce': ['18.221.219.4'],
    'ssh_bruteforce': ['13.58.98.64'],
    'dos_goldeneye': ['18.219.211.138'],
    'dos_slowloris': ['18.217.165.70'],
    'dos_slowhttp': ['13.59.126.31'],
    'dos_hulk': ['18.219.193.20'],
    'ddos_loic_http': ['18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135', '18.219.5.43',
                       '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'],
    'ddos_loic_udp': ['18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135', '18.219.5.43',
                      '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'],
    'bruteforce_web': ['18.218.115.60'],
    'bruteforce_xss': ['18.218.115.60'],
    'sql_injection': ['18.218.115.60'],
    'infiltration': ['13.58.225.34'],
    'bot': ['18.219.211.138']
}

# types = ['ftp_bruteforce', 'ssh_bruteforce', 'dos_goldeneye', 'dos_slowloris', 'dos_slowhttp', 'dos_hulk',
#          'ddos_loic_http', 'ddos_loic_udp', 'bruteforce_web', 'bruteforce_xss', 'sql_injection', 'infiltration', 'bot']

# types = ['dos_slowhttp', 'dos_hulk']
types = ['ddos_loic_udp']

attack_pcap_root = '/home/hierdetect/0_data/3_cicids2018_new/attack_pcap'
fix_attack_pcap_root = '/home/hierdetect/0_data/3_cicids2018_new/fix_attack_pcap'

for ct in types:
    print('[INFO] Process '+ct)
    ori_paths = type2path[ct]
    ips = type2ip[ct]
    for path in ori_paths:
        print('[INFO] Process '+path)
        try:
            path_1 = path
            path_2 = os.path.join(attack_pcap_root, ct+'-'+path.split('/')[-1])
            if len(ips) == 1:
                cmd1 = 'tshark -r ' + path_1 + ' -w ' + path_2 + ' -Y "ip.addr == ' + ips[0] + '"'
            else:
                tmp = ' or '.join('(ip.addr==' + i + ')' for i in ips)
                cmd1 = 'tshark -r ' + path_1 + ' -w ' + path_2 + ' -Y "' + tmp + '"'
            print('[INFO] Execute ' + cmd1)
            subprocess.call(cmd1, shell=True)

            path_3 = os.path.join(fix_attack_pcap_root, 'fix_' + path.split('/')[-1])
            cmd2 = 'editcap -F pcap ' + path_2 + ' ' + path_3
            print('[INFO] Execute ' + cmd2)
            subprocess.call(cmd2, shell=True)

        except Exception as e:
            print('[ERROR] Error occurs. ')
            traceback.print_exc()