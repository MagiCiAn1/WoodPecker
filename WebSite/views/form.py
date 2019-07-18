# -*- coding: UTF-8 –*-
from captcha.fields import CaptchaField, CaptchaTextInput
from django import forms
class loginForm(forms.Form):
    email = forms.CharField(label='邮箱', max_length=50, widget=forms.TextInput(attrs={'class': 'inp','placeholder':'Email',
                                                                                     'autocomplete':'off', '_v-61b6f824': ''}))
    password = forms.CharField(label='密码', max_length=50, widget=forms.PasswordInput(attrs={'class': 'inp','placeholder': 'Password',
                                                                                            'autocomplete':'off', '_v-61b6f824': ''}))
    captcha = CaptchaField(label = '验证码')

class registerForm(forms.Form):
    username = forms.CharField(label='用户名', max_length=50, widget=forms.TextInput(attrs={'class': 'inp','placeholder':'Username',
                                                                                    '_v-af1df450': ''}))
    password = forms.CharField(label='密码', max_length=50,
                               widget=forms.PasswordInput(attrs={'class': 'inp', 'placeholder': 'Password',
                                                             '_v-af1df450': ''}))
    confirm_password = forms.CharField(label='密码', max_length=50,
                               widget=forms.PasswordInput(attrs={'class': 'inp', 'placeholder': 'Confirm Password',
                                                                 '_v-af1df450': ''}))
    captcha = CaptchaField(label='验证码')