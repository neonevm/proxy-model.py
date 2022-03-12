from abc import ABCMeta, abstractmethod


class INeonAppImpl(metaclass=ABCMeta):

    @abstractmethod
    def run_impl(self):
        """Implements application logic"""


class NeonApp:

    def run(self: INeonAppImpl) -> int:
        try:
            self.run_impl()
        except Exception as err:
            self.error(f'Failed to start {self.__class__.__name__}: {err}')
            return 1
        return 0
