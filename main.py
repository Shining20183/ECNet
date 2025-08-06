#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@Modify Time      @Author    @Version    @Desciption
------------      -------    --------    -----------
2023/11/20 21:19      1.0       
'''

import csv
import math
import os
import random

import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from torch.utils.data import TensorDataset, DataLoader
import torch.nn.functional as F
from torch.nn import MultiheadAttention

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

import pandas as pd
import numpy as np

from torch.autograd import Variable

import logging

use_gpu = torch.cuda.is_available()
device = torch.device('cuda' if torch.cuda.is_available else 'cpu')

print('device: ', device)


class Config:
    def __init__(self):
        self.name = 'fusion_mix_ids2018_with_standard_conf_dropout_declinelmbda_0_3_hardsample_p02_s04'
        self.log_file = 'log/' + self.name + '.txt'

        self.train_normal_root = '/home/hierdetect/0_data/3_cicids2018_new/combine_feat/normal_split/train'
        self.test_normal_root = '/home/hierdetect/0_data/3_cicids2018_new/combine_feat/normal_split/test'
        self.train_attack_root = '/home/hierdetect/0_data/3_cicids2018_new/combine_feat/attack_split/mix_train'
        self.test_attack_root = '/home/hierdetect/0_data/3_cicids2018_new/combine_feat/attack_split/mix_test'
        self.train_normal_path = [os.path.join(self.train_normal_root, file) for file in
                                  os.listdir(self.train_normal_root)]
        self.test_normal_path = [os.path.join(self.test_normal_root, file) for file in
                                 os.listdir(self.test_normal_root)]
        self.train_attack_path = [os.path.join(self.train_attack_root, file) for file in
                                  os.listdir(self.train_attack_root)]
        self.test_attack_path = [os.path.join(self.test_attack_root, file) for file in
                                 os.listdir(self.test_attack_root)]

        self.packet_num = 4
        self.packet_size = 200
        self.ld_num = 3
        self.ld_size = 20  # 之前是200，现在变成了200
        self.packet_cols = ['packet_' + str(i + 1) for i in range(self.packet_num)]
        self.ld_cols = ['ld_' + str(i + 1) for i in range(self.ld_num)]

        self.batch_size = 128
        self.train_epoch = 30
        self.model_path = 'model_' + self.name
        if not os.path.exists(self.model_path):
            os.mkdir(self.model_path)

        # 所有的正常数据都加载进来
        self.normal_num = None
        self.attack_num = 10000

        # self.normal_num = 5000
        # self.attack_num = 100

        self.packet_noise_per = 0.2
        self.session_row_noise_per = 0.4
        self.session_col_noise_num = 4


def read_single(file_path, config, n=None):
    # print('process ' + file_path)
    data = pd.read_csv(file_path, nrows=n, dtype=str)
    data = data.applymap(lambda x: [int(i) for i in x.split(',')])
    for ld_col in config.ld_cols:
        data[ld_col] = data[ld_col].apply(lambda x: x[:config.ld_size])

    # 先把这些数据都变成一行的，便于处理
    data_packet = np.array(data[config.packet_cols].values.tolist()).reshape(
        [-1, config.packet_num * config.packet_size])
    data_session = np.array(data[config.ld_cols].values.tolist()).reshape([-1, config.ld_num * config.ld_size])
    out_data = np.concatenate([data_packet, data_session], axis=1)
    return out_data


def add_noise(data, packet_noise_per, session_row_noise_per, session_col_noise_num):
    '''
    :param data:
    :param packet_noise_per: 有多少行(占比多少)需要在数据包上增加噪声
    :param session_row_noise_per: 有多少行(占比多少)要在会话(包长序列)上添加噪声
    :param session_col_noise_num: 每一行有多少个值要扰动
    :return:
    '''
    row_num = len(data)
    packet_data = data[:, : config.packet_num * config.packet_size]
    session_data = data[:, config.packet_num * config.packet_size:]

    # 给数据包增加噪声
    packet_noise_num = int(row_num * packet_noise_per)
    row_indices_packet = np.random.choice(row_num, size=packet_noise_num, replace=False)
    # print(row_indices_packet)

    for row_index_p in row_indices_packet:
        section = np.random.randint(0, config.packet_num)
        start = section * config.packet_size
        end = start + config.packet_size
        packet_data[row_index_p, start:end] = 0

    # 给会话增加噪声
    session_noise_num = int(row_num * session_row_noise_per)
    row_indices_session = np.random.choice(row_num, size=session_noise_num, replace=False)
    # print(row_indices_session)
    for row_index_s in row_indices_session:
        col_index = np.random.choice(range(config.ld_num * config.ld_size), size=session_col_noise_num, replace=False)
        tmp = [1, -1] * session_col_noise_num
        for i in range(len(col_index)):
            session_data[row_index_s, col_index[i]] += tmp[i]
            if session_data[row_index_s, col_index[i]] < 0:
                # 如果减去1之后小于0了,那还是0
                session_data[row_index_s, col_index[i]] = 0

    new_data = np.concatenate([packet_data, session_data], axis=1)
    return new_data


# 在计算confidence的时候使用的
def encode_onehot(labels, n_classes):
    onehot = torch.FloatTensor(labels.size()[0], n_classes)
    labels = labels.data
    if labels.is_cuda:
        onehot = onehot.cuda()
    onehot.zero_()
    onehot.scatter_(1, labels.view(-1, 1), 1)
    return onehot


class PacketCNN(nn.Module):
    def __init__(self):
        super(PacketCNN, self).__init__()
        self.conv1 = nn.Conv1d(1, 16, 3)
        self.conv2 = nn.Conv1d(16, 32, 5)
        self.conv3 = nn.Conv1d(32, 64, 3)
        self.fc1 = nn.Linear(576, 128)
        self.dropout1 = nn.Dropout(0.4)
        self.fc2 = nn.Linear(128, 64)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = F.max_pool1d(x, 3)
        x = F.relu(self.conv2(x))
        x = F.max_pool1d(x, 3)
        x = F.relu(self.conv3(x))
        x = F.max_pool1d(x, 2)
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = self.dropout1(x)
        x = self.fc2(x)
        return x


class AttCNN(nn.Module):
    def __init__(self):
        super(AttCNN, self).__init__()
        self.cnn = PacketCNN()
        self.att = MultiheadAttention(64, num_heads=4)
        self.fc1 = nn.Linear(64, 32)
        self.dropout1 = nn.Dropout(0.4)
        self.fc2 = nn.Linear(32, 16)

    def forward(self, x):
        # input: [batch_size, packet_num_in_session, packet_dim]
        # 将每个包转化为单独的元素
        # 之前这里使用的是view，但会报错，换为reshape
        x = x.reshape(-1, 200).unsqueeze(1)  # [batch_size*packet_num_in_session, packet_dim]
        x = self.cnn(x)  # [batch_size*packet_num_in_session, packet_dim_after_cnn]
        # 转化回会话格式，每个会话中4个包，cnn的输出维度是64
        x = x.view(-1, 4, 64)  # [batch_size, packet_num_in_session, packet_dim_after_cnn]
        # 调整顺序
        x = x.transpose(0,
                        1)  # [packet_num_in_session, batch_size, packet_dim_after_cnn] = [sequence_length, batch_size, embed_size])
        att_out, att_out_weight = self.att(x, x, x)
        avg_att = torch.mean(att_out, dim=0)
        out = F.relu(self.fc1(avg_att))
        out = self.dropout1(out)
        out = self.fc2(out)
        return out


class SessionCNN(nn.Module):
    def __init__(self):
        super(SessionCNN, self).__init__()
        self.conv1 = nn.Conv2d(1, 16, (2, 3))  # 假设输入有1个频道
        self.conv2 = nn.Conv2d(16, 32, (2, 5))
        self.fc1 = nn.Linear(32, 24)
        self.dropout1 = nn.Dropout(0.4)
        self.fc2 = nn.Linear(24, 16)

    def forward(self, x):
        x = F.relu(self.conv1(x))
        x = F.max_pool2d(x, (1, 2))
        x = F.relu(self.conv2(x))
        x = F.max_pool2d(x, (1, 3))
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        x = self.dropout1(x)
        x = self.fc2(x)
        return x


class FusionModel(nn.Module):
    def __init__(self):
        super(FusionModel, self).__init__()
        self.attcnn = AttCNN()
        self.sessioncnn = SessionCNN()
        self.bilinear1 = nn.Bilinear(16, 16, 16)
        self.bilinear2 = nn.Bilinear(16, 16, 16)
        self.fc1 = nn.Linear(32, 8)
        self.dropout1 = nn.Dropout(0.4)
        self.fc2 = nn.Linear(8, 2)

        self.c_fc1 = nn.Linear(32, 8)
        self.dropout2 = nn.Dropout(0.4)
        self.c_fc2 = nn.Linear(8, 1)

    def forward(self, x):
        px = x[:, :config.packet_num * config.packet_size]
        sx = x[:, config.packet_num * config.packet_size:]
        px = px.reshape([-1, config.packet_num, config.packet_size])
        sx = sx.reshape([-1, config.ld_num, config.ld_size]).unsqueeze(1)

        # get feature
        p_out = self.attcnn(px)
        s_out = self.sessioncnn(sx)

        # feature fusion
        a_1 = self.bilinear1(p_out, s_out)
        a_1 = F.sigmoid(a_1)
        a_2 = self.bilinear2(s_out, p_out)
        a_2 = F.sigmoid(a_2)
        p_out_new = torch.mul(a_1, p_out)
        s_out_new = torch.mul(a_2, s_out)
        fusion_feature = torch.concat([p_out_new, s_out_new], dim=1)

        # output data
        out = F.relu(self.fc1(fusion_feature))
        out = self.dropout1(out)
        out = self.fc2(out)

        c = self.c_fc1(fusion_feature)
        c = self.dropout2(c)
        c = self.c_fc2(c)
        return out, c


config = Config()
logging.basicConfig(filename=config.log_file, filemode='a', level=logging.DEBUG, format='%(message)s')
logging.info('\n\n=========================\n\n')
logging.info('[INFO] Execute ' + config.name + '.py \n')
logging.info('para: packet_noise_per=' + str(config.packet_noise_per) + ', session_row_noise_per=' + str(
    config.session_row_noise_per)
             + ', session_col_noise_num=' + str(config.session_col_noise_num))

# load train data
# train_normal_data_arr_tmp = [read_single(path, config, config.normal_num) for path in config.train_normal_path]
# train_normal_data_arr = [i for i in train_normal_data_arr_tmp if len(i) != 0]
# train_normal_data_arr_noise = [
#     add_noise(data, config.packet_noise_per, config.session_row_noise_per, config.session_col_noise_num) for data in
#     train_normal_data_arr]
# train_normal_data = np.concatenate(train_normal_data_arr_noise, axis=0)
# train_normal_label = [0] * len(train_normal_data)
# print('train normal num: ', len(train_normal_data))
# logging.info('train normal num: ' + str(len(train_normal_data)))
#
# train_attack_data_arr_tmp = [read_single(path, config, config.attack_num) for path in config.train_attack_path]
# train_attack_data_arr = [i for i in train_attack_data_arr_tmp if len(i) != 0]
# train_attack_data_arr_noise = [
#     add_noise(data, config.packet_noise_per, config.session_row_noise_per, config.session_col_noise_num) for data in
#     train_attack_data_arr]
# train_attack_data = np.concatenate(train_attack_data_arr_noise, axis=0)
# train_attack_label = [1] * len(train_attack_data)
# print('train attack num: ', len(train_attack_data))
# logging.info('train attack num: ' + str(len(train_attack_data)))
#
# train_data = np.concatenate([train_normal_data, train_attack_data], axis=0)
# train_label = train_normal_label + train_attack_label
#
# del train_normal_data_arr_tmp, train_normal_data_arr, train_normal_data, train_normal_label, train_normal_data_arr_noise
# del train_attack_data_arr_tmp, train_attack_data_arr, train_attack_data, train_attack_label, train_attack_data_arr_noise
#
# x_train = torch.FloatTensor(train_data)
# y_train = torch.LongTensor(train_label)
# if use_gpu:
#     x_train = x_train.cuda()
#     y_train = y_train.cuda()
#
# train_dataset = TensorDataset(x_train, y_train)
# train_loader = DataLoader(train_dataset, batch_size=config.batch_size, shuffle=True)

# load test data
test_normal_data_arr_tmp = [read_single(path, config, config.normal_num) for path in config.test_normal_path]
test_normal_data_arr = [i for i in test_normal_data_arr_tmp if len(i) != 0]
test_normal_data = np.concatenate(test_normal_data_arr, axis=0)
test_normal_label = [0] * len(test_normal_data)
print('test normal num: ', len(test_normal_data))
logging.info('test normal num: ' + str(len(test_normal_data)))

test_attack_data_arr_tmp = [read_single(path, config, config.attack_num) for path in config.test_attack_path]
test_attack_data_arr = [i for i in test_attack_data_arr_tmp if len(i) != 0]
test_attack_data = np.concatenate(test_attack_data_arr, axis=0)
test_attack_label = [1] * len(test_attack_data)
print('test attack num: ', len(test_attack_data))
logging.info('test attack num: ' + str(len(test_attack_data)))

test_data = np.concatenate([test_normal_data, test_attack_data], axis=0)
test_label = test_normal_label + test_attack_label

del test_normal_data_arr_tmp, test_normal_data_arr, test_normal_data, test_normal_label
del test_attack_data_arr_tmp, test_attack_data_arr, test_attack_data, test_attack_label

x_test = torch.FloatTensor(test_data)
y_test = torch.LongTensor(test_label)

if use_gpu:
    x_test = x_test.cuda()
    y_test = y_test.cuda()

test_dataset = TensorDataset(x_test, y_test)
test_loader = DataLoader(test_dataset, batch_size=config.batch_size, shuffle=False)

print('[INFO] Finish load data')

# print('[INFO] Begin train model')
#
# model = FusionModel()
# if use_gpu:
#     model = model.cuda()
#
# optimizer = optim.Adam(model.parameters(), lr=0.001)
# criterion = nn.CrossEntropyLoss()
#
# criterion_with_conf = nn.NLLLoss()
#
# model.train()
# for epoch in range(config.train_epoch):
#     total_loss = 0
#     lmbda_initial = 0.3
#     total_entropy_loss = 0
#     total_conf_loss = 0
#     for batch_idx, (data, target) in enumerate(train_loader):
#         # print('batch ', batch_idx)
#         step = int(batch_idx / 50) + 1
#         optimizer.zero_grad()
#         output, confidence = model(data)
#         pred_original = F.softmax(output, dim=1)
#         confidence = F.sigmoid(confidence)
#         eps = 1e-12
#
#         # 限制pred和confidence的范围
#         pred_original = torch.clamp(pred_original, 0. + eps, 1. - eps)
#         confidence = torch.clamp(confidence, 0. + eps, 1. - eps)
#
#         # 随机选一半数据，将conf设为1，不使用hints
#         b = Variable(torch.bernoulli(torch.Tensor(confidence.size()).uniform_(0, 1))).cuda()
#         conf = confidence * b + (1 - b)
#
#         # 计算有提示参与的概率
#         labels_onehot = Variable(encode_onehot(target, 2))
#         pred_new_ = pred_original * conf.expand_as(pred_original) + labels_onehot * (1 - conf.expand_as(labels_onehot))
#         pred_new = torch.log(pred_new_)
#
#         # 计算总loss
#         xentropy_loss = criterion_with_conf(pred_new, target)
#         confidence_loss = torch.mean(-torch.log(confidence))
#
#         lmbda = lmbda_initial * math.exp(-step / 50)
#
#         # lmbda = 0.1
#         # budget = 0.3
#         combine_loss = xentropy_loss + (lmbda * confidence_loss)
#         # print(' lmbda: ', lmbda)
#         # print(' confidence loss: ', confidence_loss)
#         # print(' xentropy loss:   ', xentropy_loss)
#
#         # if budget > confidence_loss.data:
#         #     lmbda = lmbda / 1.01
#         # elif budget <= confidence_loss.data:
#         #     lmbda = lmbda / 0.99
#
#         combine_loss.backward()
#         optimizer.step()
#
#         total_loss += combine_loss.item()
#         total_entropy_loss += xentropy_loss.item()
#         total_conf_loss += confidence_loss.item()
#
#     print(f"Epoch {epoch + 1}, Loss: {total_loss}, Entropy loss: {total_entropy_loss}, Conf loss: {total_conf_loss}")
#     logging.info('Epoch ' + str(epoch + 1) + ', Loss: ' + str(total_loss) + ', Entropy loss: ' + str(total_entropy_loss)
#                  + ', Conf loss: ' + str(total_conf_loss))
#     torch.save(model.state_dict(), config.model_path + '/fusion_' + str(epoch) + '.pth')

print('[INFO] Begin test')


def eval_model(epoch):
    print('===')
    logging.info('==== test model ====')
    model = FusionModel()
    loaded_model_path = config.model_path + '/fusion_' + str(epoch) + '.pth'
    if use_gpu:
        model.load_state_dict(torch.load(loaded_model_path))
        model.to('cuda')
    else:
        model.load_state_dict(torch.load(loaded_model_path, map_location='cpu'))
    print('[INFO] Finish load model: ', loaded_model_path)
    logging.info('load model from ' + loaded_model_path)

    model.eval()

    y_label = []
    y_pre = []
    y_prob = []
    y_conf = []

    with torch.no_grad():
        for batch_idx, (test_data, test_target) in enumerate(test_loader):
            test_output, test_confidence = model(test_data)
            prob = F.softmax(test_output, dim=1)
            conf = F.sigmoid(test_confidence).data.view(-1)
            _, pred = torch.max(prob.data, 1)
            y_prob.append(prob)
            y_label.append(test_target)
            y_pre.append(pred)
            y_conf.append(conf)

    print('[INFO] Finish test')
    y_label = torch.concat(y_label, dim=0)
    y_pre = torch.concat(y_pre, dim=0)
    y_prob = torch.concat(y_prob, dim=0)
    y_conf = torch.concat(y_conf, dim=0)

    if use_gpu:
        y_label = y_label.cpu()
        y_pre = y_pre.cpu()
        y_prob = y_prob.cpu()
        y_conf = y_conf.cpu()

    acc = accuracy_score(y_label, y_pre)
    pre = precision_score(y_label, y_pre)
    rec = recall_score(y_label, y_pre)
    f1 = f1_score(y_label, y_pre)
    print('acc: ', acc)
    print('pre: ', pre)
    print('rec: ', rec)
    print('f1 : ', f1)
    logging.info('\n Test result:')
    logging.info('acc: ' + str(acc))
    logging.info('pre: ' + str(pre))
    logging.info('rec: ' + str(rec))
    logging.info('f1: ' + str(f1))

    cm = confusion_matrix(y_label, y_pre)
    print('confusion matrix:')
    print(cm)
    logging.info('confusion matrix: ')
    logging.info(cm)

    pre_lab = torch.concat([y_prob, y_label.unsqueeze(1), y_pre.unsqueeze(1), y_conf.unsqueeze(1)], dim=1)
    df = pd.DataFrame(pre_lab.numpy(), columns=['prob_0', 'prob_1', 'label', 'pred', 'conf'])
    df.to_csv('prob_packet_fusion_mix_ids2018_stand_conf_epoch' + str(epoch) + '_dropout_declinelambda_0_3_hardsample_p02_s04.csv', index=False)


eval_model(28)