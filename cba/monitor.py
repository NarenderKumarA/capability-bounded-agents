"""Reference monitor: deterministic, OUT-OF-MODEL enforcement of a capability contract.

Every tool call an agent wants to make is checked here BEFORE it executes. The decision
depends only on (a) the declared contract and (b) the concrete call arguments — never on
the model's prompt or output. That independence is the whole point: prompt injection can
make the model *try* anything, but it cannot change what the monitor *permits*.

This is the formal object the paper's soundness argument is about:
    A bounded action a  is executable  ==>  a is permitted by the contract.
The contrapositive (a not permitted ==> a never executes) holds for ALL model outputs,
so containment is invariant under adversarial context.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


@dataclass
class Capability:
    name: str
    allowed: bool = False                              # default-DENY
    arg_check: Optional[Callable[[dict], bool]] = None  # optional constraint on arguments


@dataclass
class CapabilityContract:
    """The declared permission envelope. Anything not explicitly allowed is denied."""
    caps: Dict[str, Capability] = field(default_factory=dict)

    def allow(self, name: str, arg_check: Optional[Callable[[dict], bool]] = None) -> "CapabilityContract":
        self.caps[name] = Capability(name, allowed=True, arg_check=arg_check)
        return self


@dataclass
class Decision:
    permitted: bool
    reason: str


class ReferenceMonitor:
    """Mediates every tool call. Pure function of (contract, call) — no model in the loop."""

    def __init__(self, contract: CapabilityContract):
        self.contract = contract

    def check(self, name: str, args: dict) -> Decision:
        cap = self.contract.caps.get(name)
        if cap is None or not cap.allowed:
            return Decision(False, f"'{name}' is not in the capability contract (default-deny)")
        if cap.arg_check is not None and not cap.arg_check(args):
            return Decision(False, f"'{name}' arguments violate the contract constraint: {args}")
        return Decision(True, "within contract")
