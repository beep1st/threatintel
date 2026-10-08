"""Read local credentials without committing them to source control."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / '.env')


def get_env(name):
    return os.environ.get(name, '')
