"""Existing multi-view RRF retrieval with the frozen V8 union-cost selector."""
import numpy as np
from .budget_evidence_v7 import _group_order
from .group_completion import build_pool


class RankedGroups:
    def __init__(self,groups,order):self.groups=groups;self.order=order
    def __getattr__(self,name):return getattr(self.groups,name)
    def __len__(self):return len(self.groups)
    def ranked_descriptors(self,values,ties):return self.order


def build_rrf_pool(data,primary,rarity,path_view,groups,routes,mandatory,cap=32768,max_examined=327680,rrf_c=60):
    order=_group_order(groups,primary,rarity,path_view,data['tie'],'rrf',rrf_c)
    pool,diag=build_pool(data,primary,RankedGroups(groups,order),routes,mandatory,cap,max_examined)
    diag.update(rank_policy='rrf',rrf_c=rrf_c,revision='r4; same V8 scoring/objective/path contract; three original unlabeled ranking views')
    return pool,diag
