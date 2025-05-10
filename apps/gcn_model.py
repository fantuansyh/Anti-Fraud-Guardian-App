from androguard.misc import AnalyzeAPK
import pandas as pd
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModel
from torch import nn

class graph_constructor(nn.Module):
    def __init__(self, num_nodes, embed_dim, ):
        super(graph_constructor, self).__init__()
        self.nodes = num_nodes
        self.emb_dim = embed_dim

        self.embed = nn.Parameter(torch.randn(self.nodes, embed_dim))

        self.norm_static = nn.LayerNorm(embed_dim)

    def forward(self):
        nodevec = self.norm_static(self.embed)  # 对节点嵌入向量进行标准化操作

        adj = torch.relu(torch.mm(nodevec, nodevec.transpose(0, 1)))
        adj = torch.softmax(adj, dim=-1)  # 邻接矩阵
        return adj


class gconv(nn.Module):
    def __init__(self):
        super(gconv, self).__init__()

    def forward(self, x, A):
        # X: B,N,d
        # A: N,N
        x = torch.einsum('vw, nwd->nvd', [A, x])
        return x.contiguous()


class MYmodel(nn.Module):
    def __init__(self, in_dim, hidden, out_dim, layers, num_nodes, embed_dim):
        super(MYmodel, self).__init__()
        self.layers = layers

        self.graph_construct = graph_constructor(num_nodes, embed_dim)

        self.lin_start = nn.Linear(in_dim, hidden)

        self.gcn = nn.ModuleList()
        self.lin_hiddens = nn.ModuleList()
        self.dropouts = nn.ModuleList()
        self.norms = nn.ModuleList()
        for i in range(layers):
            self.gcn.append(gconv())
            self.lin_hiddens.append(nn.Linear(hidden, hidden))
            self.dropouts.append(nn.Dropout(p=0.1))
            self.norms.append(nn.LayerNorm(hidden))


        self.alpha = nn.Linear(hidden,1)
        self.w = nn.Parameter(torch.randn(num_nodes,hidden,hidden))
        # self.lin_end = nn.Linear(hidden, out_dim)
        self.lin_end = nn.Sequential(nn.Linear(hidden,hidden),nn.ReLU(),nn.Linear(hidden,out_dim))

    def forward(self, x):
        # 最开始的特征维度变换
        x = self.lin_start(x)
        # 用于构造邻接矩阵
        A = self.graph_construct()
        residual = x
        for i in range(self.layers):

            # 邻接矩阵和节点表示相乘
            x = self.gcn[i](x, A)  # 用了简单的相乘
            # 节点表示的特征变换
            x = self.lin_hiddens[i](x)
            # x = self.dropouts[i](x)
            x = torch.relu(x)

            # layernorm
            x = self.norms[i](x)
        x = residual + x
        # x = torch.mean(x, dim=1)
        x = torch.einsum("bnd,ndf->bf",x,self.w)
        # x = torch.squeeze(x,dim=1)
        x = self.lin_end(x)
        return x
def extract_features(apk_path):
    features = []
    try:
        print(f"Reading file: {apk_path}")
        apk, _, dx = AnalyzeAPK(apk_path)
        permissions = apk.get_permissions()
        apis = extract_apis(dx)
        actions = extract_actions(dx)
        features.append({
            'permissions': permissions,
            'apis': apis,
            'actions': actions
        })
    except Exception as e:
        print(f"Error analyzing {apk_path}: {e}")
    return features

def extract_apis(dx):
    apis = set()
    for method in dx.get_methods():
        for _, call, _ in method.get_xref_to():
            apis.add(call.class_name + "->" + call.name)
    return list(apis)

# 提取action特征
def extract_actions(dx):
    actions = set()
    for method in dx.get_methods():
        for _, ref, _ in method.get_xref_from():
            if ref.class_name.startswith('Landroid/content/Intent') and 'action' in ref.name.lower():
                actions.add(ref.class_name + "->" + ref.name)
    return list(actions)

def preprocess_features(features):
    preprocessed_features = []
    for feature in features:
        combined_features = ' '.join(feature['permissions']) + ' ' + ' '.join(feature['apis']) + ' ' + ' '.join(feature['actions'])
        preprocessed_features.append(combined_features)
    return preprocessed_features

def encode_features(model, tokenizer, sentences, device):
    encoded_features = []
    model.to(device)
    model.eval()
    for sentence in sentences:
        inputs = tokenizer(sentence, return_tensors='pt', truncation=True, padding=True, max_length=512)
        inputs = {key: val.to(device) for key, val in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs)
            vector = outputs.last_hidden_state.mean(dim=1).squeeze().cpu().numpy()
        encoded_features.append(vector)
    return encoded_features

def create_feature_sequences(encoded_features):
    feature_sequences = np.array(encoded_features)
    return feature_sequences


