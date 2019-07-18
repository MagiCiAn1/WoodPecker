# -*- coding: UTF-8 –*-
from datetime import datetime

from django.shortcuts import render
from django.http import HttpResponse, StreamingHttpResponse
import json
import logging
import hashlib
import os
from WoodPecker.settings import BASE_DIR
from . import settings
from WebSite.models import FileModel

HTTP_BAD_REQUEST = 400


def index(request):
    context = {'version': settings.VERSION, 'login': '../login/'}
    template = 'general/index.html'
    return render(request, template, context)


def home(request):
    user_name = request.session.get('user_name')
    template = 'general/person.html'
    return render(request, template, {'username': user_name})


def history(request):
    user_id = request.session.get('user_id')
    result = []
    try:
        models = FileModel.objects.filter(user_id=user_id).order_by("modify_time")
        for item in models:
            dic = {}
            dic['name'] = item.name
            dic['md5'] = item.md5
            dic['size'] = item.size
            dic['time'] = item.modify_time
            result.append(dic)
    except Exception as e:
        logging.error(e)
    template = 'general/history.html'
    return render(request, template, {'models': result})


def images(request, app_id):
    icon_file = os.path.join(settings.ICON_FILES, app_id + '.png')
    with open(icon_file, 'rb') as file:
        image_data = file.read()
    return HttpResponse(image_data, content_type="image/png")


def download_apk(request, md5):
    def file_iterator(file_name, chunk_size=512):
        with open(file_name) as f:
            while True:
                c = f.read(chunk_size)
                if c:
                    yield c
                else:
                    break

    file = os.path.join(settings.DIRECTORY_APK_FILES, md5 + '.apk')
    response = StreamingHttpResponse(file_iterator(file))
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="%s.apk"' % md5
    return response


def download_pdf(request, md5):
    def file_iterator(file_name, chunk_size=512):
        with open(file_name, 'rb') as f:
            while True:
                c = f.read(chunk_size)
                if c:
                    yield c
                else:
                    break

    file = os.path.join(settings.REPORT_FILES, md5 + '.pdf')
    response = StreamingHttpResponse(file_iterator(file))
    response['Content-Type'] = 'application/octet-stream'
    response['Content-Disposition'] = 'attachment;filename="%s.pdf"' % md5
    return response


class Upload(object):
    def __init__(self, request):
        self.__data = None
        self.__user_id = request.session.get('user_id', -1)
        self.__method = request.method
        self.__file = request.FILES.get('file')
        self.__file_name = request.FILES.get('file').name
        self.__file_type = ''
        self.__response_data = {
            'url': '../analyzer/',
            'description': '',
            'status': ''
        }
        valid = self.is_valid_file()
        if valid is True:
            logging.info("the file is valid..")
            md5 = self.file_md5()
            status, msg = self.save_file(md5)
            if status:
                self.__response_data['url'] = '../analyzer/?md5={}&&type={}'.format(md5, self.__file_type)
            else:
                self.__response_data['description'] = 'Server error'
                self.__response_data['status'] = 'error'

    def get_resp(self):
        resp = HttpResponse(json.dumps(self.__response_data),
                            content_type="application/json; charset=utf-8")
        resp['Access-Control-Allow-Origin'] = '*'
        return resp

    def is_valid_file(self):
        if self.__method == 'POST':
            try:
                self.__file_type = self.__file_name.split('.')[-1].lower()
                if self.__file_type == 'apk' or self.__file_type == 'zip':
                    self.__response_data['description'] = ''
                    self.__response_data['status'] = 'success'
                    return True
                else:
                    logging.log(logging.ERROR, 'File format not Supported!')
                    self.__response_data['description'] = 'File format not Supported!'
                    self.__response_data['status'] = 'error'
            except:
                logging.log(logging.ERROR, 'File format not Supported!')
                self.__response_data['description'] = 'File format not Supported!'
                self.__response_data['status'] = 'error'
        else:
            self.__response_data['description'] = 'Method not Supported!'
            self.__response_data['status'] = 'error'
        return False

    def file_md5(self):
        md5 = hashlib.md5()
        for chunk in self.__file.chunks():
            md5.update(chunk)
        md5sum = md5.hexdigest()
        return md5sum

    def save_file(self, md5):
        try:
            files = FileModel.objects.filter(md5=md5)
            if len(files) == 0:
                logging.info("the file is first upload.we are should saved it.")
                file_path = os.path.join(BASE_DIR, settings.DIRECTORY_APK_FILES, md5 + '.' + self.__file_type)
                logging.info("the file will be saved at %s" % file_path)
                try:
                    with open(file_path, "wb+") as file:
                        for chunk in self.__file.chunks():
                            file.write(chunk)
                except:
                    logging.error("save file error")
                    return False, "save file error"
                # logging.info(self.__file.size)
                if (self.__user_id > 0):
                    file = FileModel.objects.create(name=self.__file_name, md5=md5, size=self.__file.size,
                                                    save_path=file_path,
                                                    user_id=self.__user_id)
                    data = {
                        "id": file.id,
                        "name": file.name,
                        "save_path": file.save_path,
                        "md5": file.md5,
                        "size": file.size,
                        "first":True
                    }
                    self.__response_data['data'] = data
                    return True, "upload success"
                else:
                    logging.error("login user error")
                    return False, 'upload error'

            else:
                logging.info("the file has been upload.")
                file = files[0]
                file.modify_time = datetime.utcnow()
                file.save()
                # file.update(modify_time=datetime.utcnow())
                data = {
                    "id": file.id,
                    "name": file.name,
                    "save_path": file.save_path,
                    "md5": file.md5,
                    "size": file.size,
                    "first":False
                }
                self.__response_data['data'] = data
                return True, None
        except Exception as e:
            logging.error(e)
            return False, e

    @staticmethod
    def as_view(request):
        print('as_view')
        upload = Upload(request)
        return upload.get_resp()


def search(request):
    response_data = {
        'url': '../analyzer/',
        'description': '',
        'status': ''
    }
    if request.method == 'GET':
        md5 = request.GET.get("md5", 0)
        if len(md5) == 32:
            logging.info("search file by md5 %s" % md5)
            try:
                files = FileModel.objects.filter(md5=md5)
                if len(files) == 0:
                    logging.info("not searched file by md5 %s" % md5)
                    response_data['description'] = 'The file was not found.'
                    response_data['status'] = 'error'
                else:
                    logging.info("search file success")
                    file = files[0]
                    data = {
                        "id": file.id,
                        "name": file.name,
                        "save_path": file.save_path,
                        "md5": file.md5,
                        "size": file.size
                    }
                    response_data['description'] = ''
                    response_data['status'] = 'success'
                    response_data['url'] = '../analyzer/'
                    response_data['data'] = data
            except Exception as e:
                logging.error(e)
        else:
            logging.info("md5 value error,return")
            response_data['description'] = 'This is not Md5!'
            response_data['status'] = 'error'
    else:
        response_data['description'] = 'Method not Supported!'
        response_data['status'] = 'error'
    resp = HttpResponse(json.dumps(response_data),
                        content_type="application/json; charset=utf-8")
    resp['Access-Control-Allow-Origin'] = '*'
    return resp
