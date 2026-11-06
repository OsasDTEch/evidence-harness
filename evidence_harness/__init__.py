"""evidence-harness: an eval harness that is a system of record that happens to test.

Every run writes a contemporaneous, hash-verified manifest: what was asked for,
what actually answered, the raw payloads, the criteria fixed before the run,
repeated samples per case, all chained into append-only storage.
"""

__version__ = "0.1.0"
