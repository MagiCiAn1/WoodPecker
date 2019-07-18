"""WoodPecker URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin

from StaticAnalyzer.views import analyse
from WebSite.views import home, user
from WebSite.admin import admin_site
urlpatterns = [
    url(r'^admin/',admin_site.urls),
    url(r'^/', home.index),
    url(r'^index/', home.index),
    url(r'^login/', user.login),
    url(r'^captcha/', include('captcha.urls')),
    url(r'^refresh/', user.refresh_code),
    url(r'^register/', user.register),
    url(r'^sendEmailCode/', user.send_email_code),
    url(r'^verify/', user.verify_email_code),
    url(r'^search/', home.search),
    # url('^', home.index),
    url(r'^upload/', home.Upload.as_view),
    url(r'^analyzer/', analyse.start),
    url(r'^home/', home.home),
    url(r'^history/', home.history),
    url(r'^images/(?P<app_id>.+)/icon/$', home.images, name='images'),
    url(r'^download/(?P<md5>.+)/apk/$', home.download_apk, name='apk'),
    url(r'^download/(?P<md5>.+)/pdf/$', home.download_pdf, name='pdf'),
]
