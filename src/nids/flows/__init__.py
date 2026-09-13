"""Flow aggregation: groups packets into bidirectional flows and produces the
fixed-width feature vectors both the rule engine and the ML model consume.
"""

from nids.flows.flow import FlowRecord
from nids.flows.flow_tracker import FlowTracker

__all__ = ["FlowRecord", "FlowTracker"]
