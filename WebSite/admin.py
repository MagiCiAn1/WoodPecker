# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from models import User,FileModel

# Register your models here.
class MyAdminSite(admin.AdminSite):
    site_header = '后台管理'
    site_title = '后台管理'
    site_url = '/index/'
admin_site = MyAdminSite()
admin_site.register([User, FileModel])
