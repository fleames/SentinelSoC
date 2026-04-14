# ASCII-only source: valid UTF-8 on all platforms.
"""
sentinel_soc.py -- Thin entrypoint for the Sentinel SOC dashboard.

Loads persisted state, creates the Flask app, and starts background threads
when executed directly.  When imported by a WSGI server (gunicorn, uWSGI),
only the ``app`` object is used; callers must invoke
``start_background_threads(app)`` themselves if needed.
"""

from sentinel.persistence import (
    _ensure_state_dir,
    _ensure_audit_file,
    _load_bans,
    _load_parsed_state,
    _load_behavior_state,
    _load_history_buckets,
    _prune_history_event_files,
)
from sentinel.app import create_app, start_background_threads
from sentinel.settings import load as _load_settings

_ensure_state_dir()
_ensure_audit_file()
_load_settings()   # apply any persisted runtime overrides before threads start
_load_bans()
_load_parsed_state()
_load_behavior_state()
_load_history_buckets()
_prune_history_event_files()

app = create_app()

if __name__ == "__main__":
    start_background_threads(app)
    app.run(host="0.0.0.0", port=5000, threaded=True)
