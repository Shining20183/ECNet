#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/11/14 14:15        1.0      将pcap文件按照会话切分，提取数据包信息
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

types = ['ftp_bruteforce', 'ssh_bruteforce', 'dos_goldeneye', 'dos_slowloris', 'dos_slowhttp', 'dos_hulk',
         'ddos_loic_http', 'ddos_loic_udp', 'bruteforce_web', 'bruteforce_xss', 'sql_injection', 'infiltration', 'bot']

fix_attack_pcap_root = '/home/hierdetect/0_data/3_cicids2018_new/fix_attack_pcap'
splitted_pcap = '/home/hierdetect/0_data/3_cicids2018_new/splitted_attack'
splitted_csv_root = '/home/hierdetect/0_data/3_cicids2018_new/splitted_packet_csv/attack'

for ct in types:
    print('[INFO] Process '+ct)
    ori_paths = type2path[ct]
    for path in ori_paths:
        try:
            print('[INFO] Process ' + path)
            path_3 = os.path.join(fix_attack_pcap_root, ct + '-fix_' + path.split('/')[-1])  # 已经被筛选的都是攻击流量的pcap
            tar_splitted_root = os.path.join(splitted_pcap, ct + '-split_' + path.split('/')[-1])
            if not os.path.exists(tar_splitted_root):
                os.mkdir(tar_splitted_root)
            tar_packet_csv_path = os.path.join(splitted_csv_root, 'split-' + ct + '-' + path.split('/')[-1] + '.csv')
            tar_index_csv_path = os.path.join(splitted_csv_root, 'index-' + ct + '-' + path.split('/')[-1] + '.csv')

            print('[INFO] Begin splitcap')
            cmd = 'mono SplitCap.exe -r ' + path_3 + ' -o ' + tar_splitted_root + ' -p 1018'
            subprocess.call(cmd, shell=True)
            print('[INFO] Finish splitcap')

            print('[INFO] Begin extract feature from each folder')
            pcapfolder2csv(tar_splitted_root, tar_packet_csv_path, tar_index_csv_path)
            print('[INFO] Finish extract feature')
        except Exception as e:
            traceback.print_exc()



