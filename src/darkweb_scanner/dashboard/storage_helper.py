"""
Shared storage accessor — avoids circular imports between app.py and route modules.
"""

from ..storage import Storage

_storage = None


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage
