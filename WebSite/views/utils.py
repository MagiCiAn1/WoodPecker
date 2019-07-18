#!/bin/usr/env python2.7
# -*- coding: utf-8 -*-
# Author:Magician
# CreateTime:2019/4/13 23:40
import smtplib
from email.mime.text import MIMEText

class SendEmail(object):
    def __init__(self, address, msg):
        # 设置服务器所需信息
        # 163邮箱服务器地址
        self.mail_host = 'smtp.qq.com'
        # 163用户名
        # self.mail_user = '17806254838'
        # qq邮箱发送方
        self.mail_user = '1325151621@qq.com'
        # 密码(部分邮箱为授权码)
        # self.mail_pass = 'q980118'
        self.mail_pass ='lfhjdxroigzpbaaa'
        # self.sender = '17806254838@163.com'
        # self.address = []
        # if type(address) !=list:
        #     self.address = [address]
        self.address = address
        # 设置email信息
        # 邮件内容设置
        desc = '您好\n\n以下是您注册 WoodPecker 移动安全平台账号时所需的验证码\n\n%s\n\n您收到这封邮件，是由于您在 WoodPecker 移动安全平台进行新用户注册使用了这个邮箱地址。如果您并没有访问过WoodPecker移动安全平台，或没有进行上述操作，请忽略这封邮件。您不需要退订或进行其他进一步的操作。\n\nWoodPecker移动安全平台 管理团队.'%msg
        self.message = MIMEText(desc, 'plain', 'utf-8')
        # 邮件主题
        self.message['Subject'] = 'WoodPecker移动安全平台Email注册验证'
        # 发送方信息
        self.message['From'] = self.mail_user
        # 接受方信息
        self.message['To'] = address

    def send(self):
        # 登录并发送邮件
        try:
            # smtpObj = smtplib.SMTP()
            # 连接到服务器
            smtpObj = smtplib.SMTP_SSL(self.mail_host, 465)
            # 登录到服务器
            print smtpObj.login(self.mail_user, self.mail_pass)
            # 发送
            print smtpObj.sendmail(
                self.mail_user, self.address, self.message.as_string())
            # 退出
            smtpObj.quit()
            return 'ok',''
        except smtplib.SMTPException as e:
            print e
            return 'error', e

if __name__ == '__main__':
    send_email_object = SendEmail('2592226744@qq.com', '123456')
    send_email_object.send()