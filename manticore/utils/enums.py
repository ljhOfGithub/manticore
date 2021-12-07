from enum import Enum


class StateLists(Enum):
    """
    The set of StateLists tracked in ManticoreBase在ManticoreBase追踪的一组状态名单
    """

    ready = "READY"
    busy = "BUSY"
    terminated = "TERMINATED"
    killed = "KILLED"


class StateStatus(Enum):
    """
    Statuses that a StateDescriptor can have状态描述符可以拥有的状态
    """

    waiting_for_worker = "waiting_for_worker"
    waiting_for_solver = "waiting_for_solver"
    running = "running"
    #: Killed OR Terminated
    stopped = "stopped"
    #: Removed
    destroyed = "destroyed"


class MProcessingType(Enum):
    """Used as configuration constant for choosing multiprocessing flavor"""
    """用作选择多进程偏好的配置常数"""
    multiprocessing = "multiprocessing"
    single = "single"
    threading = "threading"

    def title(self):
        return self._name_.title()

    @classmethod
    def from_string(cls, name):
        return cls.__members__[name]

    def to_class(self):
        return globals()[f"Manticore{self.title()}"]


class Sha3Type(Enum):
    """Used as configuration constant for choosing sha3 flavor"""
    """作为sha3偏好选择的配置常数"""
    concretize = "concretize"
    symbolicate = "symbolicate"
    fake = "fake"

    def title(self):
        return self._name_.title()

    @classmethod
    def from_string(cls, name):
        return cls.__members__[name]


class DetectorClassification(Enum):
    """
    Shall be consistent with
    https://github.com/trailofbits/slither/blob/563d5118298e4cae7f0ea5f2a531f0dcdcebd64d/slither/detectors/abstract_detector.py#L11-L15
    """
    #和slither一致

    HIGH = 0
    MEDIUM = 1
    LOW = 2
    INFORMATIONAL = 3
