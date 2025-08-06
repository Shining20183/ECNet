#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/11/16 22:29        1.0              获取会话信息
'''

import os
import subprocess
import csv
import dpkt
import socket
import traceback


def get_pcap_folder_info(folder_path, csv_path):
    csvfile = open(csv_path, 'w', newline='')
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(
        ['filename', 'first_ts', 'src_ip', 'dst_ip', 'sport', 'dport', 'protocol', 'directions', 'lengths'])

    for pcapfile in os.listdir(folder_path):
        pcapfile_path = os.path.join(folder_path, pcapfile)
        pcap_f = open(pcapfile_path, 'rb')
        pcap = dpkt.pcap.Reader(pcap_f)
        row = [pcapfile]
        lengths = []
        directions = []
        index = 0

        first_src = 0

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            packet_len = len(buf)
            lengths.append(packet_len)

            # 过滤非IP包
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            # 解析IP层
            ip = eth.data
            # 获取源和目的IP地址
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if index == 0:
                # 初始化协议类型和端口
                protocol_type = 'IP'
                src_port = None
                dst_port = None
                first_src = src_ip

                # 判断具体的协议类型（TCP, UDP）
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    protocol_type = 'TCP'
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    protocol_type = 'UDP'
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport

                row.append(ts)
                row.append(src_ip)
                row.append(dst_ip)
                row.append(src_port)
                row.append(dst_port)
                row.append(protocol_type)

            if src_ip == first_src:
                directions.append(1)
            else:
                directions.append(-1)

            index += 1

        lengths_str = ','.join([str(i) for i in lengths])
        directions_str = ','.join([str(i) for i in directions])
        row.append(directions_str)
        row.append(lengths_str)
        csvwriter.writerow(row)


# session_info_root = '/home/hierdetect/0_data/1_cicids2018/session_info'
# # folders = '/home/hierdetect/0_data/1_cicids2018/splitted_attack/split_5_0214_30min_11_00-11_30_mixed.pcap'
#
#
# folder_root = '/home/hierdetect/0_data/1_cicids2018/splitted_attack'
#
# for folders in os.listdir(folder_root):
#     print('[INFO] Process '+folders)
#     session_info_path = os.path.join(session_info_root, folders.split('/')[-1][:-5]+'.csv')
#     get_pcap_folder_info(os.path.join(folder_root, folders), session_info_path)


session_info_root_attack = '/home/hierdetect/0_data/3_cicids2018_new/session_info/attack'
folder_root_attack = '/home/hierdetect/0_data/3_cicids2018_new/splitted_attack'
for folders in os.listdir(folder_root_attack):
    print('[INFO] Process ' + folders)
    session_info_path = os.path.join(session_info_root_attack, folders.split('/')[-1][:-5] + '.csv')
    if os.path.exists(session_info_path):
        print(' exists, skip')
    else:
        get_pcap_folder_info(os.path.join(folder_root_attack, folders), session_info_path)

session_info_root_normal = '/home/hierdetect/0_data/3_cicids2018_new/session_info/normal'
folder_root_normal = '/home/hierdetect/0_data/3_cicids2018_new/splitted_normal'
for folders in os.listdir(folder_root_normal):
    print('[INFO] Process ' + folders)
    session_info_path = os.path.join(session_info_root_normal, folders.split('/')[-1][:-5] + '.csv')
    if os.path.exists(session_info_path):
        print(' exists, skip')
    else:
        get_pcap_folder_info(os.path.join(folder_root_normal, folders), session_info_path)
