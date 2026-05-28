from abc import ABC, abstractmethod
import angr


class BasicScase(ABC):
    @abstractmethod
    def __init__(self, cftrace, dftrace, arch):
        pass

    @abstractmethod
    def prune_states(self, simgr: angr.SimulationManager):
        pass