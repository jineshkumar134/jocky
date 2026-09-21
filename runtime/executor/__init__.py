"""runtime/executor package — public re-exports."""
from .dispatcher import OperationDispatcher, OperationResult
from .executor import InvestigationExecutionResult, RuntimeExecutor

__all__ = [
    "OperationDispatcher",
    "OperationResult",
    "InvestigationExecutionResult",
    "RuntimeExecutor",
]
