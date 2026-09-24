"""Adapters around pinned, unmodified public graph algorithm kernels.

These are NOT full G-Retriever, OmicsIntegrator or VLDB-paper reproductions.
"""
from __future__ import annotations
import numpy as np


def local_degree_scores(src,dst,node_count):
    import networkit as nk
    nk.setNumberOfThreads(1)
    pairs=np.column_stack((np.minimum(src,dst),np.maximum(src,dst)))
    unique,inverse=np.unique(pairs,axis=0,return_inverse=True)
    graph=nk.Graph(node_count,directed=False,weighted=False)
    for a,b in unique:graph.addEdge(int(a),int(b))
    graph.indexEdges()
    raw=nk.sparsification.LocalDegreeSparsifier().scores(graph)
    values=np.asarray([raw[graph.edgeId(int(a),int(b))] for a,b in unique])
    return values[inverse]


def pcst_edges(src,dst,edge_prize,raw_cost,seed_nodes,multiplier):
    """Native PCST with edge-prize virtual nodes, as in G-Retriever's transform.

    Costs use raw episode cardinality. Zero-cost super-root links expose all
    POI endpoints. Output can have several real components after super-root
    removal, and is not a directed/time-respecting graph guarantee.
    """
    from pcst_fast import pcst_fast
    if multiplier<=0:raise ValueError('positive cost multiplier required')
    n=int(max(np.max(src),np.max(dst)))+1;root=n
    edges=[];costs=[];mapping=[];virtual={};prizes=[0.]*(n+1)
    for i,(a,b,value,cost) in enumerate(zip(src,dst,edge_prize,raw_cost)):
        cost=float(cost)*multiplier
        if value<=cost:
            edges.append((int(a),int(b)));costs.append(cost-float(value));mapping.append(i)
        else:
            node=len(prizes);prizes.append(float(value)-cost);virtual[node]=i
            edges.extend([(int(a),node),(node,int(b))]);costs.extend([0.,0.]);mapping.extend([-1,-1])
    for v in np.unique(seed_nodes):edges.append((root,int(v)));costs.append(0.);mapping.append(-1)
    vertices,chosen=pcst_fast(np.asarray(edges,np.int64),np.asarray(prizes,float),np.asarray(costs,float),root,1,'gw',0)
    keep=np.zeros(len(src),bool)
    for e in chosen:
        original=mapping[int(e)]
        if original>=0:keep[original]=True
    for v in vertices:
        if int(v) in virtual:keep[virtual[int(v)]]=True
    return keep
