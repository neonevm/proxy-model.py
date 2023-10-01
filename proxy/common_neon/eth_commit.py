from typing import NewType


class EthCommit:
    Type = NewType('EthCommit', str)

    NotProcessed = Type('not-processed')
    Pending = Type('pending')
    Latest = Type('latest')
    Safe = Type('safe')
    Finalized = Type('finalized')
    Earliest = Type('earliest')

    @staticmethod
    def to_type(value: str) -> Type:
        if isinstance(value, str):
            value = EthCommit.Type(value)
            if value in {EthCommit.Pending, EthCommit.Latest, EthCommit.Safe, EthCommit.Finalized, EthCommit.Earliest}:
                return value

        assert False, 'Wrong commitment level'
