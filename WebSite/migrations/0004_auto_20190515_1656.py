# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-05-15 08:56
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('WebSite', '0003_auto_20190412_1042'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(default='123', max_length=50, unique=True),
        ),
    ]