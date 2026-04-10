"""Ai:oS Meta-Agents Package"""

# Lazy imports — agents are imported on demand to avoid heavy dependency chains.
__all__ = [
    'KernelAgent',
    'SecurityAgent',
    'NetworkingAgent',
    'ApplicationAgent',
    'ScalabilityAgent',
    'OrchestrationAgent',
    'UserAgent',
    'GuiAgent',
]


def __getattr__(name: str):
    """Lazy-load agent classes on first access."""
    _map = {
        'KernelAgent': 'agents.kernel_agent',
        'SecurityAgent': 'agents.security_agent',
        'NetworkingAgent': 'agents.networking_agent',
        'ApplicationAgent': 'agents.application_agent',
        'ScalabilityAgent': 'agents.scalability_agent',
        'OrchestrationAgent': 'agents.orchestration_agent',
    }
    if name in _map:
        import importlib
        mod = importlib.import_module(_map[name])
        return getattr(mod, name)
    raise AttributeError(f"module 'agents' has no attribute {name!r}")
