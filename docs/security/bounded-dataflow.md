# Bounded Python dataflow v1

The first native flow model answers one narrow question: within one Python
function, can a parameter be followed through direct assignments, concatenation
or an explicit transform argument to `eval`/`exec`, or to a supported
`subprocess` call with the direct literal option `shell=True`?

It builds no cross-file graph, imports no framework model and claims neither
attacker control nor exploitability. The public signal contains only the fixed
flow kind, portable path, source/sink byte ranges and assignment-hop count. It
contains no source text, identifier, command or parameter name.

The evaluator is bounded to 100,000 visited nodes, 4,096 facts, 128 tracked
variables per function, eight assignment hops and the shared parser deadline.
Unsupported statements, ambiguous taint operations, malformed syntax or any
exhausted bound set `bounded_dataflow` coverage to `partial`; the engine does not
publish a false zero. Other source languages are `unsupported` for this domain.

Facts are serialized using
[`bounded-dataflow-signal-v1.schema.json`](../../schemas/bounded-dataflow-signal-v1.schema.json).
Use them to prioritize review or compare with an isolated research tool such as
Joern. Do not use array length as a full flow count unless domain coverage is
`complete`.
