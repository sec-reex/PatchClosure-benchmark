# Oslo namespace compatibility for Kilo-era Glance.
# Installed packages expose oslo_config / oslo_i18n / ... ; Glance 2015 still
# does `from oslo.config import cfg` and `import oslo.utils.importutils`.
# This is NOT a Glance stub.
#
# Important: do not bind sys.modules["oslo.utils"] to the oslo_utils module
# object itself. Python 2 only loads oslo.utils.importutils if the parent
# module's __name__ is "oslo.utils" (parent.__name__ + ".importutils").
import sys
import types

_oslo = sys.modules.get("oslo")
if _oslo is None:
    _oslo = types.ModuleType("oslo")
    _oslo.__path__ = []
    sys.modules["oslo"] = _oslo


def _alias_oslo_package(short):
    """oslo.<short> -> a package named oslo.<short> with oslo_<short>'s path."""
    real_name = "oslo_" + short
    alias = "oslo." + short
    if alias in sys.modules and getattr(sys.modules[alias], "__name__", None) == alias:
        return sys.modules[alias]
    __import__(real_name)
    real = sys.modules[real_name]
    pkg = types.ModuleType(alias)
    pkg.__file__ = getattr(real, "__file__", None)
    pkg.__path__ = list(getattr(real, "__path__", []) or [])
    pkg.__package__ = alias
    for key, value in real.__dict__.items():
        if key in ("__name__", "__package__", "__path__"):
            continue
        setattr(pkg, key, value)
    sys.modules[alias] = pkg
    setattr(sys.modules["oslo"], short, pkg)
    return pkg


class _OsloAliasImporter(object):
    def find_module(self, name, path=None):
        if not name.startswith("oslo.") or name.startswith("oslo._"):
            return None
        rest = name[5:]
        first, sep, tail = rest.partition(".")
        try:
            __import__("oslo_" + first)
        except ImportError:
            return None
        if not sep:
            return self
        # oslo.utils.importutils: alias the parent, then load the real submodule
        # and expose it under the oslo.* name. Standard import also works once
        # the parent alias has __name__ == "oslo.utils" and the real __path__.
        try:
            __import__("oslo_" + first + "." + tail)
        except ImportError:
            return None
        return self

    def load_module(self, name):
        if name in sys.modules and name != "oslo":
            existing = sys.modules[name]
            if getattr(existing, "__name__", None) == name:
                return existing
        rest = name[5:]
        first, sep, tail = rest.partition(".")
        if not sep:
            return _alias_oslo_package(first)
        parent = _alias_oslo_package(first)
        real_name = "oslo_" + first + "." + tail
        __import__(real_name)
        real = sys.modules[real_name]
        sys.modules[name] = real
        child = tail.split(".")[-1]
        setattr(parent, child, real)
        return real


if not any(isinstance(f, _OsloAliasImporter) for f in sys.meta_path):
    sys.meta_path.insert(0, _OsloAliasImporter())
