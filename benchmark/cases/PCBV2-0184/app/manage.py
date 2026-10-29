#!/usr/bin/env python
"""Standard Django manage.py for the real-app Truncator ReDoS benchmark project."""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proj.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
