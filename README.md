# ECNet

Official Implementation of “ECNet: Robust Malicious Network Traffic Detection With Multi-View Feature and Confidence Mechanism”

How to run
1. seperate normal and attack pcap
   - data_preprocess/get_normal_packet.py
   - data_preprocess/get_attack_packet.py
2. get content features
   - data_preprocess/get_normal_packet_seq.py
   - data_preprocess/get_attack_packet_seq.py
3. get pattern features
   - data_preprocess/get_session_info.py
4. train and test
   - main.py
