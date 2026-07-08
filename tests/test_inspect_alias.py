"""`inspect` shadows the stdlib module; `inspect_input` is the documented name."""

from promptpaws import inspect, inspect_input
from promptpaws.firewall import inspect as firewall_inspect
from promptpaws.firewall import inspect_input as firewall_inspect_input


def test_inspect_is_an_alias_for_inspect_input():
    assert inspect is inspect_input
    assert firewall_inspect is firewall_inspect_input
