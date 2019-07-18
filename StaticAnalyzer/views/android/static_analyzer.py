# coding:utf-8
import os
from time import time

from django.shortcuts import render

from StaticAnalyzer.views.android.manifest_analyze import ManifestAnalyze
from androguard.core.bytecodes import apk
from datetime import datetime
import logging
from xml.dom import minidom

from WebSite.views.settings import DIRECTORY_APK_FILES

from .apk_wrapped import ApkDetect
from .code_analyze import CodeAnalyze
from StaticAnalyzer.models import Bugs

class AndroidAnalyzer(object):
    def __init__(self, md5):
        self.__apk_file_name = os.path.join(DIRECTORY_APK_FILES, md5 + '.apk')
        self.__apk = apk.APK(self.__apk_file_name)
        self.__xml = minidom.parseString(self.__apk.get_android_manifest_axml().get_buff())
        self.__start_time = datetime.utcnow()
        self.__md5 = md5

    def check_wrapped(self):
        return ApkDetect.has_wrapped(self.__apk)

    def start_analyze(self):
        logging.info("start analyze...")
        start = time()
        wrapped = self.check_wrapped()

        # self.__apk.get_icon()
        manifest_analyze = ManifestAnalyze(self.__apk, self.__apk_file_name, self.__xml, self.__md5)
        apk_info = manifest_analyze.get_apk_info()
        apk_info['wrapped'] = wrapped
        signature = manifest_analyze.get_signature()
        permission = manifest_analyze.get_all_permission()
        # allow_backup = manifest_analyze.allow_backup()
        # debuggable = manifest_analyze.debuggable()
        #
        # test_only = manifest_analyze.is_testonly()
        exported_activity = manifest_analyze.get_export_assembly()  # Brodcast recevier 缺少动态注册的
        # print(exported_activity)
        # print time.time()-start
        code_analyze = CodeAnalyze(self.__apk)
        code_analyze_result = []
        bugs = Bugs.objects.filter(is_test=1)
        # code_analyze.string_regex()
        # code_analyze.base64_regex()
        # su,exc = code_analyze.exec_search()
        # print code_analyze.has_debug_check()
        # print code_analyze.has_signature_check()
        for item in bugs:
            item_dict = {}
            item_dict['name'] = item.name
            item_dict['desc'] = item.desc
            item_dict['resolve'] = item.resolve
            result = eval(item.code)
            if type(result) == bool:
                if result == True:
                    item_dict['result'] = ['是']
                else:
                    item_dict['result'] = ['否']
            else:
                item_dict['result'] = result
            code_analyze_result.append(item_dict)
        # print code_analyze.webview_save_password_check()
        # print code_analyze.webview_file_access_check()
        # print code_analyze.webview_ssl_error_proceed()
        # print code_analyze.webview_check_server_trusted()
        # print code_analyze.not_verify_hostname()
        # print code_analyze.webview_debuggable_check()
        # code_analyze.weak_encryption()
        # code_analyze.check_init_IV()
        # code_analyze.file_world_read()
        # code_analyze.dex_class_loder()
        stop = time()
        print code_analyze_result
        print '检测用时%d s'%(stop-start)
        return {'apk_info': apk_info, 'signature': signature, 'permission': permission, 'export': exported_activity, 'bugs': code_analyze_result}
