import os
import sys
from pathlib import Path

# Ensure project root (contains manage.py and mysite/) is importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")

import django
from django.core.management import call_command
from mysite.wsgi import application


def _maybe_run_migrations() -> None:
    # In ephemeral serverless runtimes, make sure required tables exist.
    if os.environ.get("DJANGO_AUTO_MIGRATE", "1") != "1":
        return

    django.setup()
    call_command("migrate", interactive=False, run_syncdb=True, verbosity=0)


_maybe_run_migrations()

app = application
