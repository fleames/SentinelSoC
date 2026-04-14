# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel/routes/ui.py -- The / (index) route that serves the HTML dashboard.
"""
from flask import Blueprint, render_template

bp = Blueprint("ui", __name__)


@bp.route("/")
def index():
    return render_template("index.html")
