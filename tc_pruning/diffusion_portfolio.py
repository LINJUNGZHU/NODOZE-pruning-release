"""Fixed global-priority / relation-allocation budget split, no label input."""
import math
from .cross_domain_pruning import top_budget
from .temporal_diffusion import stratified_budget


def portfolio_budget(values,relations,mandatory,budget,ties,fraction=.5):
    if not 0<=fraction<=1:raise ValueError('fraction must be in [0,1]')
    if mandatory.sum()>budget:raise ValueError('infeasible raw cap')
    prefix=max(int(mandatory.sum()),math.floor(budget*fraction))
    kept=top_budget(values,mandatory,prefix,ties)
    return stratified_budget(values,relations,kept,budget,ties)
