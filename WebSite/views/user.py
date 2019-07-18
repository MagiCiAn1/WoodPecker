#!/bin/usr/env python2.7
# -*- coding: utf-8 -*-
# Author:Magician
# CreateTime:2019/4/18 18:53
import ast
import json
import random
import re

from captcha.helpers import captcha_image_url
from captcha.models import CaptchaStore
from django.http import HttpResponse
from django.shortcuts import redirect, render

from WebSite import models
from WebSite.views import form
from WebSite.views.utils import SendEmail


def login(request):
    if request.method == 'POST':
        login_form = form.loginForm(request.POST)
        message = "验证码错误！"
        hash_key = CaptchaStore.generate_key()
        image_url = captcha_image_url(hash_key)
        if login_form.is_valid():
            email = login_form.cleaned_data['email']
            password = login_form.cleaned_data['password']
            try:
                user = models.User.objects.get(email=email)
                if user.password == password:
                    request.session['user_id'] = user.id
                    request.session['user_name'] =user.username
                    return redirect('/home/')
                else:
                    message = "密码不正确！"
            except Exception as e:
                print e
                message = "用户不存在！"
        return render(request, 'general/login.html', locals())
    else:
        login_form = form.loginForm()
        hash_key = CaptchaStore.generate_key()
        image_url = captcha_image_url(hash_key)
        return render(request, 'general/login.html', locals())


def refresh_code(request):
    hash_key = CaptchaStore.generate_key()
    image_url = captcha_image_url(hash_key)
    resp = HttpResponse(json.dumps({'hash_key': hash_key, 'image_url': image_url}),
                        content_type="application/json; charset=utf-8")
    resp['Access-Control-Allow-Origin'] = '*'
    return resp


def register(request):
    if request.method == 'POST':
        register_form = form.registerForm(request.POST)
        message = "验证码错误！"
        hash_key = CaptchaStore.generate_key()
        image_url = captcha_image_url(hash_key)
        step = 1
        if register_form.is_valid():
            email = request.session.get('email', '')
            username = register_form.cleaned_data['username']
            password = register_form.cleaned_data['password']
            if username != '' and password != '' and email != '':
                try:
                    try:
                        user = models.User.objects.get(email=email)
                        message = '该用户已存在'
                    except models.User.DoesNotExist:
                        user = models.User.objects.create(email=email, username=username, password=password)
                        if user:
                            message = "注册成功"
                            return redirect('/home/')
                        else:
                            message = "注册失败"
                except:
                    message = "注册失败！"
        return render(request, 'general/register.html', locals())
    else:
        register_form = form.registerForm()
        hash_key = CaptchaStore.generate_key()
        image_url = captcha_image_url(hash_key)
        return render(request, 'general/register.html', locals())


def send_email_code(request):
    if request.method == 'POST':
        res_json = {
            'code': 0,
            'message': ''
        }
        try:
            email = ast.literal_eval(request.body).get('email', '')
            regex = '^([A-Za-z0-9_\-\.])+\@([A-Za-z0-9_\-\.])+\.([A-Za-z]{2,4})$'
            if re.match(regex, email) is not None:
                code = ''
                for i in range(0, 6):
                    code += str(random.randrange(0, 10))
                print code
                error = 'ok'
                send_object = SendEmail(email, code)
                error,msg = send_object.send()
                if error == 'ok':
                    request.session['email_code'] = code
                    request.session['email'] = email
                    res_json['message'] = '验证码发送成功'
                else:
                    res_json['code'] = 1
                    res_json['message'] = '验证码发送失败'

            else:
                res_json['code'] = 1
                res_json['message'] = '邮箱格式不正确'
        except Exception as e:
            res_json['code'] = 1
            res_json['message'] = '邮箱格式不正确'
        resp = HttpResponse(json.dumps(res_json),
                            content_type="application/json; charset=utf-8")
        return resp


def verify_email_code(request):
    right_code = request.session.get('email_code')
    right_email = request.session.get('email')
    res_json = {
        'code': 0,
        'message': ''
    }
    if request.method == 'POST':
        try:
            email = ast.literal_eval(request.body).get('email', '')
            code = ast.literal_eval(request.body).get('code', '')
            if code == right_code and email == right_email:
                res_json['code'] = 0
                res_json['message'] = '验证码正确'
            else:
                res_json['code'] = 1
                res_json['message'] = '验证码输入错误'
        except Exception as e:
            res_json['code'] = 1
            res_json['message'] = '未知错误'
    else:
        res_json['code'] = 1
        res_json['message'] = '未知错误'
    resp = HttpResponse(json.dumps(res_json),
                        content_type="application/json; charset=utf-8")
    return resp


def personal_center(request):
    pass

if __name__ == '__main__':
    pass
