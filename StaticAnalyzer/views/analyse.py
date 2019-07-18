import os

from django.shortcuts import render
from django.http import HttpResponse
import logging
import pdfkit
from django.template import Context
from django.template.loader import get_template
from WoodPecker.settings import BASE_DIR
from WebSite.models import FileModel

from .android.static_analyzer import AndroidAnalyzer


def start(request):
    # logging.info("get name" + request.POST.get('name'))
    type = request.GET.get('type').encode('utf-8')
    md5 = request.GET.get('md5').encode('utf-8')
    if type == 'apk':
        android = AndroidAnalyzer(md5)
        result = android.start_analyze()
        template = get_template('general/report.html')
        html = template.render(result)
        config = pdfkit.configuration(wkhtmltopdf=r"D:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")
        css = [os.path.join(BASE_DIR, 'static/bootstrap/css/bootstrap.css')]
        pdf_file = os.path.join(BASE_DIR, 'report_file', md5 + '.pdf')
        try:
            pdfkit.from_string(html, pdf_file, configuration=config, css=css)
            FileModel.objects.filter(md5= md5).update(pdf_path=pdf_file)
        except Exception as e:
            logging.error(e)

    return render(request, 'general/report1.html', result)
