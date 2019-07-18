# -*- coding: utf-8 -*-
# Generated by Django 1.11.20 on 2019-04-05 12:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FileModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=50)),
                ('save_path', models.CharField(max_length=50)),
                ('md5', models.CharField(max_length=32)),
                ('size', models.IntegerField()),
                ('create_time', models.DateField(auto_now_add=True)),
                ('modify_time', models.DateField(auto_now=True)),
            ],
        ),
    ]
