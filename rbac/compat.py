"""
Adaptador para usar Flask-RBAC 0.5.0 (ultima version publicada) con Flask 3.

Flask-RBAC depende de dos APIs que Flask elimino en la version 2.3. Este modulo neutraliza el import y sobreescribe solo los dos metodos que
usaban esas APIs. El resto de la logica de la libreria no cambia.
"""

import flask
from flask import current_app

if not hasattr(flask, "_request_ctx_stack"):
    # Solo hace falta para que el import funcione; get_app() ya no lo usa.
    flask._request_ctx_stack = None

from flask_rbac import RBAC as _RBAC  # noqa: E402
from flask_rbac import _RBACState  # noqa: E402
from flask_rbac.model import anonymous  # noqa: E402


class RBAC(_RBAC):
    """RBAC compatible con Flask 3."""

    def init_app(self, app):
        app.config.setdefault("RBAC_USE_WHITE", False)
        self.use_white = app.config["RBAC_USE_WHITE"]

        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["rbac"] = _RBACState(self, app)

        self.acl.allow(anonymous, "GET", "static")
        # Sin before_first_request: _check_permission() ya construye la ACL
        # la primera vez que se evalua un permiso (acl.seted es False).
        app.before_request(self._authenticate)

    def get_app(self, reference_app=None):
        if reference_app is not None:
            return reference_app
        if self.app is not None:
            return self.app
        return current_app._get_current_object()
