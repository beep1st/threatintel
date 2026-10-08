# Threat Intelligence

A Django threat intelligence project with feed ingestion, threat actor and MITRE data integration, and a chatbot interface.

## Local configuration

Copy `.env.example` to `.env` and set a unique Django secret key and your provider API keys. Existing local credentials are kept in `.env`, which is excluded from Git.

Install the packages in `requirements.txt` in a Python virtual environment. Some features also import machine learning packages such as PyTorch and Transformers; the existing requirements list may need additional dependencies for those features.

Run database migrations with `python manage.py migrate`, then start the development server with `python manage.py runserver` after installing the needed dependencies.

The local database, uploaded media, downloaded model/CVE caches, and feed state are excluded from this repository. A fresh checkout requires creating its own database and populating the feeds. The current Django settings are for development and require configuration before production deployment.
