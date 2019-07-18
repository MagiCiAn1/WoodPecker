# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from models import Bugs
from WebSite.admin import admin_site

# Register your models here.
admin_site.register(Bugs)