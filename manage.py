#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from torch import nn
import torch
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

def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SecurityGuard.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
