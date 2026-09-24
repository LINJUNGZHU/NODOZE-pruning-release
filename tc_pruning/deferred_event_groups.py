"""Compact unlabeled interaction groups; membership never implies free selection."""
from dataclasses import dataclass
import numpy as np
from .frequency_diffusion import episodes


@dataclass(frozen=True)
class GroupIndex:
    group_of:np.ndarray
    ordered_members:np.ndarray
    offsets:np.ndarray
    start_ns:np.ndarray
    end_ns:np.ndarray
    policy:str

    @classmethod
    def from_events(cls,src,dst,relation,timestamp,ties,window_ns,relation_policy='across_relations'):
        src=np.asarray(src);dst=np.asarray(dst);relation=np.asarray(relation);timestamp=np.asarray(timestamp);ties=np.asarray(ties)
        n=len(src)
        if any(len(a)!=n for a in (dst,relation,timestamp,ties)) or len(np.unique(ties))!=n:raise ValueError('misaligned arrays or duplicate event tie')
        if relation_policy not in ('across_relations','same_relation'):raise ValueError('invalid relation policy')
        rel=relation if relation_policy=='same_relation' else np.zeros(n,int)
        groups=episodes(np.minimum(src,dst),np.maximum(src,dst),rel,timestamp,window_ns)
        order=np.lexsort((ties,timestamp,groups));counts=np.bincount(groups)
        offsets=np.r_[0,np.cumsum(counts)]
        return cls(groups,order,offsets,timestamp[order[offsets[:-1]]],timestamp[order[offsets[1:]-1]],relation_policy)

    def __len__(self):return len(self.offsets)-1

    def members(self,group):
        if group<0 or group>=len(self):raise IndexError(group)
        return self.ordered_members[self.offsets[group]:self.offsets[group+1]]

    def scores(self,values):
        values=np.asarray(values,float)
        if len(values)!=len(self.group_of):raise ValueError('score length mismatch')
        return np.maximum.reduceat(values[self.ordered_members],self.offsets[:-1])

    def ranked_descriptors(self,values,ties):
        scores=self.scores(values);group_ties=np.minimum.reduceat(np.asarray(ties)[self.ordered_members],self.offsets[:-1])
        return np.lexsort((group_ties,-scores))
