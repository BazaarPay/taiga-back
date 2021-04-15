# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2021-present Kaleidos Ventures SL

from __future__ import unicode_literals

from django.db import migrations
from django.core.files import File

import uuid


def create_github_system_user(apps, schema_editor):
    # We get the model from the versioned app registry;
    # if we directly import it, it'll be the wrong version
    User = apps.get_model("users", "User")
    db_alias = schema_editor.connection.alias
    random_hash = uuid.uuid4().hex
    user = User.objects.using(db_alias).create(
        username="bitbucket-{}".format(random_hash),
        email="bitbucket-{}@taiga.io".format(random_hash),
        full_name="BitBucket",
        is_active=False,
        is_system=True,
        bio="",
    )
    f = open("taiga/hooks/bitbucket/migrations/logo.png", "rb")
    user.photo.save("logo.png", File(f))
    user.save()
    f.close()


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_auto_20141030_1132')
    ]

    operations = [
        migrations.RunPython(create_github_system_user),
    ]
