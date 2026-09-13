"""The detection engine: wires capture -> flow tracking -> signature rules +
ML anomaly scoring into a stream of findings, and the async runner that
drives it from a live NIC or a replayed pcap.
"""

from nids.detection.pipeline import Detection, DetectionEngine
from nids.detection.runner import DetectionRunner

__all__ = ["Detection", "DetectionEngine", "DetectionRunner"]
