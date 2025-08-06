#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/10/27 11:19        1.0       
'''

import os
import subprocess
import csv
import dpkt
import socket
import traceback


def pcap2csv(packet_path, csv_path):
    # 打开pcap文件
    with open(packet_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # 打开CSV文件进行写入
        with open(csv_path, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)

            # 写入CSV文件头
            csvwriter.writerow(['src_ip', 'dst_ip', 'data'])

            # 读取每一个数据包
            for _, buf in pcap:
                # 解析以太网帧
                eth = dpkt.ethernet.Ethernet(buf)

                # 检查是否是IP数据包
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    source_ip = socket.inet_ntoa(ip.src)
                    dest_ip = socket.inet_ntoa(ip.dst)

                    # 只处理tcp和udp包
                    if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                        ip_bytes = bytes(ip)

                        # 删除源IP和目标IP字段（字节12-16和16-20）
                        modified_ip_bytes = ip_bytes[:12] + ip_bytes[20:]
                        # 转化为16进制
                        modified_ip_bytes = modified_ip_bytes.hex()

                        # 写入CSV
                        csvwriter.writerow([source_ip, dest_ip, modified_ip_bytes])


# normal_path = ['/home/new_data/ori_data/0214_pcap_30min_combine/1_0214_30min_9_00-9_30_benign.pcap',
#                '/home/new_data/ori_data/0216_pcap_30min_combine/7_0216_30min_12_00-12_30_benign.pcap']

normal_path = ['/home/new_data/ori_data/0220_pcap_30min_combine/14_0220_30min_15_30-16_00_benign.pcap']

packet_root = '/home/hierdetect/0_data/1_cicids2018/packet_csv'
fix_normal_pacp_root = '/home/hierdetect/0_data/1_cicids2018/fix_normal_pcap'
if not os.path.exists(fix_normal_pacp_root):
    os.mkdir(fix_normal_pacp_root)

for path in normal_path:
    print('[INFO] Process ' + path)
    path_1 = path
    path_2 = os.path.join(fix_normal_pacp_root, 'fix_' + path.split('/')[-1])
    cmd2 = 'editcap -F pcap ' + path_1 + ' ' + path_2
    print('[INFO] Execute '+cmd2)
    subprocess.call(cmd2, shell=True)
    dst_path = os.path.join(packet_root, 'normal_' + path.split('/')[-1][:-5] + '.csv')
    pcap2csv(path_2, dst_path)
    print('[INFO] Convert pcap to csv')
