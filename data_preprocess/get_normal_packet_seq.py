#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/11/14 10:58       1.0
'''

import os
import subprocess
import csv
import dpkt
import socket
import traceback


def pcapfolder2csv(folder_path, csv_path, fileid_path):
    index_file = open(fileid_path, 'w', newline='')
    indexwriter = csv.writer(index_file)
    indexwriter.writerow(['filename', 'index', 'first_timestamp', 'packet_count'])

    csvfile = open(csv_path, 'w', newline='')
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['file_ip', 'src_ip', 'dst_ip', 'data'])

    index = 0
    for pcapfile in os.listdir(folder_path):
        pcapfile_path = os.path.join(folder_path, pcapfile)
        pcap_f = open(pcapfile_path, 'rb')
        pcap = dpkt.pcap.Reader(pcap_f)
        count = 0
        ts0 = 0
        for ts, buf in pcap:
            if count == 0:
                ts0 = ts
            count += 1
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
                    csvwriter.writerow([index, source_ip, dest_ip, modified_ip_bytes])
        indexwriter.writerow([pcapfile, index, ts0, count])
        index += 1


# normal_path = ['/home/new_data/ori_data/0220_pcap_30min_combine/14_0220_30min_15_30-16_00_benign.pcap']
# normal_path = ['/home/new_data/ori_data/0214_pcap_30min_combine/1_0214_30min_9_00-9_30_benign.pcap',
#                '/home/new_data/ori_data/0216_pcap_30min_combine/7_0216_30min_12_00-12_30_benign.pcap',
#                '/home/new_data/ori_data/0220_pcap_30min_combine/14_0220_30min_15_30-16_00_benign.pcap']


normal_path = [
    '/home/new_data/ori_data/0214_pcap_30min_combine/1_0214_30min_9_00-9_30_benign.pcap',
    '/home/new_data/ori_data/0214_pcap_30min_combine/15_0214_30min_16_00-16_30_benign.pcap',
    '/home/new_data/ori_data/0215_pcap_30min_combine/12_0215_30min_14_30-15_00_benign.pcap',
    '/home/new_data/ori_data/0215_pcap_30min_combine/15_0215_30min_16_00-16_30_benign.pcap',
    '/home/new_data/ori_data/0216_pcap_30min_combine/7_0216_30min_12_00-12_30_benign.pcap',
    '/home/new_data/ori_data/0216_pcap_30min_combine/16_0216_30min_16_30-17_00_benign.pcap',
    '/home/new_data/ori_data/0220_pcap_30min_combine/2_0220_30min_9_30-10_00_benign.pcap',
    '/home/new_data/ori_data/0220_pcap_30min_combine/15_0220_30min_16_00-16_30_benign.pcap',
    '/home/new_data/ori_data/0222_pcap_30min_combine/1_0222_30min_9_00-9_30_benign.pcap',
    '/home/new_data/ori_data/0222_pcap_30min_combine/13_0222_30min_15_00-15_30_benign.pcap',
    '/home/new_data/ori_data/0223_pcap_30min_combine/8_0223_30min_12_30-13_00_benign.pcap',
    '/home/new_data/ori_data/0223_pcap_30min_combine/16_0223_30min_16_30-17_00_benign.pcap',
    '/home/new_data/ori_data/0228_pcap_30min_combine/2_0228_30min_9_30-10_00_benign.pcap',
    '/home/new_data/ori_data/0228_pcap_30min_combine/17_0228_30min_17_00-17_30_benign.pcap',
    '/home/new_data/ori_data/0301_pcap_30min_combine/7_0301_30min_12_00-12_30_benign.pcap',
    '/home/new_data/ori_data/0301_pcap_30min_combine/15_0301_30min_16_00-16_30_benign.pcap',
    '/home/new_data/ori_data/0302_pcap_30min_combine/1_0302_30min_9_00-9_30_benign.pcap',
    '/home/new_data/ori_data/0302_pcap_30min_combine/9_0302_30min_13_00-13_30_benign.pcap'
]

fix_normal_pacp_root = '/home/hxy/hierdetect/0_data/3_cicids2018_new/fix_normal_pcap'
splitted_pcap = '/home/hxy/hierdetect/0_data/3_cicids2018_new/splitted_normal'
if not os.path.exists(splitted_pcap):
    os.mkdir(splitted_pcap)
splitted_csv_root = '/home/hxy/hierdetect/0_data/3_cicids2018_new/splitted_packet_csv'
if not os.path.exists(splitted_csv_root):
    os.mkdir(splitted_csv_root)

for path in normal_path:
    try:
        print('Process ', path)
        path_1 = path
        path_2 = os.path.join(fix_normal_pacp_root, 'fix_' + path.split('/')[-1])
        cmd2 = 'editcap -F pcap ' + path_1 + ' ' + path_2
        subprocess.call(cmd2, shell=True)
        print('[INFO] Finish fix')

        tar_splitted_root = os.path.join(splitted_pcap, 'split_' + path.split('/')[-1])
        if not os.path.exists(tar_splitted_root):
            os.mkdir(tar_splitted_root)
        tar_packet_csv_path = os.path.join(splitted_csv_root, 'split_' + path.split('/')[-1] + '.csv')
        tar_index_csv_path = os.path.join(splitted_csv_root, 'index_' + path.split('/')[-1] + '.csv')

        print('[INFO] Begin splitcap')
        cmd = 'mono SplitCap.exe -r ' + path_2 + ' -o ' + tar_splitted_root + ' -p 1018'
        subprocess.call(cmd, shell=True)
        print('[INFO] Finish splitcap')

        print('[INFO] Begin extract feature from each folder')
        pcapfolder2csv(tar_splitted_root, tar_packet_csv_path, tar_index_csv_path)
        print('[INFO] Finish extract feature')
    except Exception as e:
        print('[ERROR]')
        traceback.print_exc()

