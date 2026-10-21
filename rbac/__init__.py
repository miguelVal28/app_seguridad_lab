from flask import session
from flask_rbac import RoleMixin, UserMixin  # noqa: E402

from rbac.compat import RBAC

ROLES = {nombre: RoleMixin(nombre) for nombre in ("estudiante", "docente", "admin")}


def load_current_user():
    """Construye el usuario actual a partir del rol guardado en la sesion."""
    rol = session.get("rol")
    if rol not in ROLES:
        return None
    return UserMixin(roles=[ROLES[rol]])


__all__ = ["RBAC", "ROLES", "load_current_user"]
