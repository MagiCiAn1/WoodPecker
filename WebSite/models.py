# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models


# Create your models here.
class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.CharField(max_length=50, null=False)
    password = models.CharField(max_length=50, null=False)
    email = models.CharField(max_length=50, null=False, unique=True, default='123')

    def __unicode__(self):
        return self.username


class FileModel(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User)
    name = models.CharField(max_length=50)
    save_path = models.CharField(max_length=50)
    md5 = models.CharField(max_length=32)
    size = models.IntegerField()
    create_time = models.DateField(auto_now_add=True)
    modify_time = models.DateField(auto_now=True)
    pdf_path = models.CharField(max_length=50, default='')

    def __unicode__(self):
        return self.name
