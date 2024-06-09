# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2021-present Kaleidos INC

from .common import *
import os

#########################################
## GENERIC
#########################################

DEBUG = os.getenv('DEBUG', 'False') == 'True'

SECURE_PROXY_SSL_HEADER = os.getenv('SECURE_PROXY_SSL_HEADER', 'SECURE_PROXY_SSL_HEADER'), 'https'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB'),
        'USER': os.getenv('POSTGRES_USER'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD'),
        'HOST': os.getenv('POSTGRES_HOST'),
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
        'OPTIONS': {'sslmode': os.getenv('POSTGRES_SSLMODE', 'disable')},
        'DISABLE_SERVER_SIDE_CURSORS': os.getenv('POSTGRES_DISABLE_SERVER_SIDE_CURSORS', 'False') == 'True',
    }
}
SECRET_KEY = os.getenv('TAIGA_SECRET_KEY')

TAIGA_SITES_SCHEME = os.getenv('TAIGA_SITES_SCHEME')
TAIGA_SITES_DOMAIN = os.getenv('TAIGA_SITES_DOMAIN')
FORCE_SCRIPT_NAME = os.getenv('TAIGA_SUBPATH', '')

TAIGA_URL = f"{TAIGA_SITES_SCHEME}://{TAIGA_SITES_DOMAIN}{FORCE_SCRIPT_NAME}"
SITES = {
    "api": {"name": "api", "scheme": TAIGA_SITES_SCHEME, "domain": TAIGA_SITES_DOMAIN},
    "front": {"name": "front", "scheme": TAIGA_SITES_SCHEME, "domain": f"{TAIGA_SITES_DOMAIN}{FORCE_SCRIPT_NAME}"}
}

LANGUAGE_CODE = os.getenv("LANGUAGE_CODE", "en-us")

INSTANCE_TYPE = "D"

WEBHOOKS_ENABLED = os.getenv('WEBHOOKS_ENABLED', 'True') == 'True'
WEBHOOKS_ALLOW_PRIVATE_ADDRESS = os.getenv('WEBHOOKS_ALLOW_PRIVATE_ADDRESS', 'False') == 'True'
WEBHOOKS_ALLOW_REDIRECTS = os.getenv('WEBHOOKS_ALLOW_REDIRECTS', 'False') == 'True'

# Setting DEFAULT_PROJECT_SLUG_PREFIX to false
# removes the username from project slug
DEFAULT_PROJECT_SLUG_PREFIX = os.getenv('DEFAULT_PROJECT_SLUG_PREFIX', 'False') == 'True'

#########################################
## MEDIA
#########################################
MEDIA_URL = f"{TAIGA_URL}/media/"
DEFAULT_FILE_STORAGE = "taiga_contrib_protected.storage.ProtectedFileSystemStorage"
THUMBNAIL_DEFAULT_STORAGE = DEFAULT_FILE_STORAGE

STATIC_URL = f"{TAIGA_URL}/static/"

#########################################
## MEDIA
#########################################
MEDIA_URL = f"{TAIGA_URL}/media/"

S3_ENABLED = os.getenv('S3_ENABLED', 'False') == 'True'

if S3_ENABLED:
    INSTALLED_APPS += [
        'storages'
    ]

    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    AWS_STORAGE_BUCKET_NAME = os.getenv("AWS_STORAGE_BUCKET_NAME")
    AWS_S3_ENDPOINT_URL = os.getenv("AWS_S3_ENDPOINT_URL")

DEFAULT_FILE_STORAGE = os.getenv("DEFAULT_FILE_STORAGE", "taiga_contrib_protected.storage.ProtectedFileSystemStorage")
THUMBNAIL_DEFAULT_STORAGE = DEFAULT_FILE_STORAGE

STATIC_URL = f"{TAIGA_URL}/static/"

#########################################
## EMAIL
#########################################
# https://docs.djangoproject.com/en/3.1/topics/email/
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
CHANGE_NOTIFICATIONS_MIN_INTERVAL = 120  # seconds

DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'system@taiga.io')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'False') == 'True'
EMAIL_USE_SSL = os.getenv('EMAIL_USE_SSL', 'False') == 'True'
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = os.getenv('EMAIL_PORT', 587)
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', 'user')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', 'password')

#########################################
## SESSION
#########################################
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
CSRF_COOKIE_SECURE = os.getenv('CSRF_COOKIE_SECURE', 'True') == 'True'

#########################################
## EVENTS
#########################################
EVENTS_PUSH_BACKEND = "taiga.events.backends.rabbitmq.EventsPushBackend"

EVENTS_PUSH_BACKEND_URL = os.getenv('EVENTS_PUSH_BACKEND_URL')
if not EVENTS_PUSH_BACKEND_URL:
    EVENTS_PUSH_BACKEND_URL = f"amqp://{os.getenv('RABBITMQ_USER')}:{os.getenv('RABBITMQ_PASS')}@{os.getenv('TAIGA_EVENTS_RABBITMQ_HOST', 'taiga-events-rabbitmq')}:5672/taiga"

EVENTS_PUSH_BACKEND_OPTIONS = {
    "url": EVENTS_PUSH_BACKEND_URL
}

#########################################
## TAIGA ASYNC
#########################################
CELERY_ENABLED = os.getenv('CELERY_ENABLED', 'True') == 'True'
from kombu import Queue  # noqa

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL')
if not CELERY_BROKER_URL:
    CELERY_BROKER_URL = f"amqp://{os.getenv('RABBITMQ_USER')}:{os.getenv('RABBITMQ_PASS')}@{os.getenv('TAIGA_ASYNC_RABBITMQ_HOST', 'taiga-async-rabbitmq')}:5672/taiga"

CELERY_RESULT_BACKEND = None  # for a general installation, we don't need to store the results
CELERY_ACCEPT_CONTENT = ['pickle', ]  # Values are 'pickle', 'json', 'msgpack' and 'yaml'
CELERY_TASK_SERIALIZER = "pickle"
CELERY_RESULT_SERIALIZER = "pickle"
CELERY_TIMEZONE = os.getenv('CELERY_TIMEZONE', 'Europe/Madrid')
CELERY_TASK_DEFAULT_QUEUE = 'tasks'
CELERY_QUEUES = (
    Queue('tasks', routing_key='task.#'),
    Queue('transient', routing_key='transient.#', delivery_mode=1)
)
CELERY_TASK_DEFAULT_EXCHANGE = 'tasks'
CELERY_TASK_DEFAULT_EXCHANGE_TYPE = 'topic'
CELERY_TASK_DEFAULT_ROUTING_KEY = 'task.default'

#########################################
##  REGISTRATION
#########################################
PUBLIC_REGISTER_ENABLED = os.getenv('PUBLIC_REGISTER_ENABLED', 'False') == 'True'

#########################################
## CONTRIBS
#########################################

# SLACK
ENABLE_SLACK = os.getenv('ENABLE_SLACK', 'False') == 'True'
if ENABLE_SLACK:
    INSTALLED_APPS += [
        "taiga_contrib_slack"
    ]

# GITHUB AUTH
# WARNING: If PUBLIC_REGISTER_ENABLED == False, currently Taiga by default prevents the OAuth
# buttons to appear for both login and register
ENABLE_GITHUB_AUTH = os.getenv('ENABLE_GITHUB_AUTH', 'False') == 'True'
if PUBLIC_REGISTER_ENABLED and ENABLE_GITHUB_AUTH:
    INSTALLED_APPS += [
        "taiga_contrib_github_auth"
    ]
    GITHUB_API_CLIENT_ID = os.getenv('GITHUB_API_CLIENT_ID')
    GITHUB_API_CLIENT_SECRET = os.getenv('GITHUB_API_CLIENT_SECRET')

# GITLAB AUTH
# WARNING: If PUBLIC_REGISTER_ENABLED == False, currently Taiga by default prevents the OAuth
# buttons to appear for both login and register
ENABLE_GITLAB_AUTH = os.getenv('ENABLE_GITLAB_AUTH', 'False') == 'True'
if PUBLIC_REGISTER_ENABLED and ENABLE_GITLAB_AUTH:
    INSTALLED_APPS += [
        "taiga_contrib_gitlab_auth"
    ]
    GITLAB_API_CLIENT_ID = os.getenv('GITLAB_API_CLIENT_ID')
    GITLAB_API_CLIENT_SECRET = os.getenv('GITLAB_API_CLIENT_SECRET')
    GITLAB_URL = os.getenv('GITLAB_URL')

#########################################
## TELEMETRY
#########################################
ENABLE_TELEMETRY = os.getenv('ENABLE_TELEMETRY', 'True') == 'True'

#########################################
##  IMPORTERS
#########################################
ENABLE_GITHUB_IMPORTER = os.getenv('ENABLE_GITHUB_IMPORTER', 'False') == 'True'
if ENABLE_GITHUB_IMPORTER:
    IMPORTERS["github"] = {
        "active": True,
        "client_id": os.getenv('GITHUB_IMPORTER_CLIENT_ID'),
        "client_secret": os.getenv('GITHUB_IMPORTER_CLIENT_SECRET')
    }

ENABLE_JIRA_IMPORTER = os.getenv('ENABLE_JIRA_IMPORTER', 'False') == 'True'
if ENABLE_JIRA_IMPORTER:
    IMPORTERS["jira"] = {
        "active": True,
        "consumer_key": os.getenv('JIRA_IMPORTER_CONSUMER_KEY'),
        "cert": os.getenv('JIRA_IMPORTER_CERT'),
        "pub_cert": os.getenv('JIRA_IMPORTER_PUB_CERT')
    }

ENABLE_TRELLO_IMPORTER = os.getenv('ENABLE_TRELLO_IMPORTER', 'False') == 'True'
if ENABLE_TRELLO_IMPORTER:
    IMPORTERS["trello"] = {
        "active": True,
        "api_key": os.getenv('TRELLO_IMPORTER_API_KEY'),
        "secret_key": os.getenv('TRELLO_IMPORTER_SECRET_KEY')
    }

#########################################
##  OPENID
#########################################
# ENABLE_OPENID Plugin
ENABLE_OPENID = os.getenv('ENABLE_OPENID', 'False') == 'True'
if ENABLE_OPENID:
    INSTALLED_APPS += [
        "taiga_contrib_openid_auth"
    ]
    OPENID_USER_URL = os.getenv('OPENID_USER_URL')
    OPENID_TOKEN_URL = os.getenv('OPENID_TOKEN_URL')
    OPENID_CLIENT_ID = os.getenv('OPENID_CLIENT_ID')
    OPENID_CLIENT_SECRET = os.getenv('OPENID_CLIENT_SECRET')
    OPENID_SCOPE = os.getenv('OPENID_SCOPE')
    OPENID_ID_FIELD = "sub"
    OPENID_USERNAME_FIELD = "preferred_username"
    OPENID_FULLNAME_FIELD = "name"
    OPENID_EMAIL_FIELD = "email"


#########################################
##  SAML
#########################################
ENABLE_SAML = os.getenv('ENABLE_SAML', 'False') == 'True'

if ENABLE_SAML:
    SP_CERT = os.getenv('SP_CERT', '')
    SP_P_KEY = os.getenv('SP_P_KEY', '')
    IDP_CERT = os.getenv('IDP_CERT', '')
    IDP_P_KEY = os.getenv('IDP_P_KEY', '')
    IDP_ENTITY_ID = os.getenv('IDP_ENTITY_ID', '')
    IDP_SSO_URL = os.getenv('IDP_SSO_URL', '')
    IDP_SLO_URL = os.getenv('IDP_SLO_URL', '')
    SSO_ORG = os.getenv('SSO_ORG', 'taiga-org')
    SSO_DISPLAY_NAME = os.getenv('SSO_DISPLAY_NAME', 'Taiga Organization')
    SSO_ORG_URL = os.getenv('SSO_ORG_URL', 'https://taiga.io')
    CP_TECHNICAL_NAME = os.getenv('CP_TECHNICAL_NAME', 'Technical Contact Name')
    CP_TECHNICAL_EMAIL = os.getenv('CP_TECHNICAL_EMAIL', 'technical@example.com')
    CP_SUPPORT_NAME = os.getenv('CP_SUPPORT_NAME', 'Support Contact Name')
    CP_SUPPORT_EMAIL = os.getenv('CP_SUPPORT_EMAIL', 'support@example.com')

    INSTALLED_APPS += ["taiga_contrib_saml_auth"]

    SAML_AUTH = {
        'sp': {
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',  # Example algorithm
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            # 'entityId', 'assertionConsumerService' and 'singleLogoutService' will be set automatically.
            # 'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',

            'x509cert': f'''-----BEGIN CERTIFICATE-----
{SP_CERT}
            -----END CERTIFICATE-----''',

            'privateKey': f'''-----BEGIN RSA PRIVATE KEY-----
{SP_P_KEY}
            -----END RSA PRIVATE KEY-----''',
        },

        'idp': {
            'entityId': IDP_ENTITY_ID,
            "singleSignOnService": {
                "url": IDP_SSO_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "singleLogoutService": {
                "url": IDP_SLO_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            'x509cert': f'''-----BEGIN CERTIFICATE-----
{IDP_CERT}
            -----END CERTIFICATE-----''',
        },

        'security': {
            'nameIdEncrypted': False,
            'authnRequestsSigned': False,
            'logoutRequestSigned': False,
            'logoutResponseSigned': False,
            'signMetadata': False,
            'wantMessagesSigned': False,
            'wantAssertionsSigned': False,
            'wantNameId': True,
            'wantNameIdEncrypted': False,
            'wantAssertionsEncrypted': False,
            'allowSingleLabelDomains': True,
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
            'rejectDeprecatedAlgorithm': True
        },

        'organization': {
            'en-US': {
                'name': SSO_ORG,
                'displayname': SSO_DISPLAY_NAME,
                'url': SSO_ORG_URL,
            },
        },

        'contactPerson': {
            'technical': {
                'givenName': CP_TECHNICAL_NAME,
                'emailAddress': CP_TECHNICAL_EMAIL
            },
            'support': {
                'givenName': CP_SUPPORT_NAME,
                'emailAddress': CP_SUPPORT_EMAIL
            },
        },

        'mapping': {
            'attributes': {
                'email': 'email',
                'username': 'preferred_username',
                'full_name': 'name',
                # 'bio': 'bio',
                # 'lang': 'lang',
                # 'timezone': 'timezone',
            },
        },
    }
