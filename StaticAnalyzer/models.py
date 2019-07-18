# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
class Bugs(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=False)
    desc = models.CharField(max_length=255, null=False)
    resolve = models.CharField(max_length=255, null=False)
    is_test = models.IntegerField(null=False, default=1)
    code = models.CharField(null=False, max_length=255)
    def __unicode__(self):
        return self.name