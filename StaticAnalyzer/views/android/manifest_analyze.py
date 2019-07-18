# coding:utf-8
import logging
import os
import re
import subprocess
from datetime import datetime

from StaticAnalyzer.views.helper import Helper
from WoodPecker.settings import BASE_DIR
from .android_permissions import *

TOOLS_PATH = os.path.join(BASE_DIR, 'tools\\')
NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'


class ManifestAnalyze(object):
    def __init__(self, apk, file_name, xml, md5):
        self.__apk_file_name = file_name
        self.__xml = xml
        self.__apk = apk
        self.__md5 = md5

    def __get_element_by_tag_and_attribute(self, tag_name, attribute_name):
        for item in self.__xml.getElementsByTagName(tag_name):
            value = item.getAttributeNS(NS_ANDROID_URI, attribute_name)
            # print(value)
            if len(value) > 0:
                return value
        return None

    def get_apk_info(self):
        logging.info('starting analyzer')
        apk_info = {
            'app_name': '',
            'package_name': '',
            'app_version': '',
            'md5': self.__md5,
            'upload_time': str(datetime.utcnow()),
        }
        app_name = self.__apk.get_app_name()
        package_name = self.__apk.get_package()
        app_version = self.__apk.get_androidversion_code()
        if not Helper.isNullOrEmptyString(app_name):
            apk_info['app_name'] = app_name
        if not Helper.isNullOrEmptyString(package_name):
            apk_info['package_name'] = package_name
        if not Helper.isNullOrEmptyString(app_version):
            apk_info['app_version'] = app_version
        app_file_size = float(os.path.getsize(self.__apk_file_name)) / (1024 * 1024)
        apk_info['apk_file_size'] = '%.2fMB' % app_file_size
        # print(apk_info)
        return apk_info

    def get_signature(self):
        signa = {}
        logging.info('get signature')
        signature_file = self.__apk.get_signature_name()
        if len(signature_file) > 0:
            print('read signature file')
            cert_file = Helper.unzip_file(self.__apk_file_name, signature_file)
            if cert_file is not None:
                platform = Helper.platform_sys()
                if platform == 'Windows':
                    logging.info("start certprint")
                    args = ['java', '-jar', TOOLS_PATH + 'CertPrint.jar', cert_file]
                elif platform == 'Linux':
                    args = ['keytool', '-printcert', '-file', cert_file]
                data = subprocess.check_output(args)
                logging.info("complete certprint")
                output = str(data).decode("gbk")
                version = re.findall('Version: (.*?)\n', output)[0]
                subject = re.findall('Subject: (.*?)\n', output)[0]
                algorithm = re.findall('Algorithm: (.*?),', output)[0]
                start_time = re.findall('From: (.*?),', output)[0]
                stop_time = re.findall('To: (.*?)\]', output)[0]
                serial = re.findall('SerialNumber: \[(.*?)\]', output)[0].replace(' ', '')
                issuer = re.findall('Issuer: (.*?)\n', output)[0]
                signa['version'] = version
                signa['subject'] = subject
                signa['algorithm'] = algorithm
                signa['start_time'] = start_time
                signa['stop_time'] = stop_time
                signa['serial'] = serial
                signa['issuer'] = issuer
                logging.info('get signature finish')
                # signa['signature'] = output
                Helper.delete_file(cert_file)
                return signa
            else:
                return signa
        else:
            signa['signature'] = 'No Code Signing Certificate Found! You may not have signed it.'
            return signa

    def get_all_permission(self):
        # print(self.__axml)
        # xml_printer = axml.AXMLPrinter(self.__axml)
        logging.info('get AndroidManifest.xml')

        uses_permission = []
        declared_permissions = {}
        all_permissions = {
            'uses_permission': [],
            'declared_permissions': {}
        }
        logging.info('get uses_permission')
        for item in self.__xml.getElementsByTagName('uses-permission'):
            uses_permission.append(str(item.getAttributeNS(NS_ANDROID_URI, "name")))
        # uses_permission.append(str(item.getAttribute("android:name")))
        for item in self.__xml.getElementsByTagName('permission'):
            d_perm_name = str(item.getAttributeNS(NS_ANDROID_URI, "name"))
            d_perm_label = str(item.getAttributeNS(NS_ANDROID_URI, "label"))
            d_perm_description = str(item.getAttributeNS(NS_ANDROID_URI, "description"))
            d_perm_permission_group = str(item.getAttributeNS(NS_ANDROID_URI, "permissionGroup"))
            d_perm_protection_level = str(item.getAttributeNS(NS_ANDROID_URI, "protectionLevel"))

            d_perm_details = {
                "label": d_perm_label,
                "description": d_perm_description,
                "permissionGroup": d_perm_permission_group,
                "protectionLevel": PERMISSION_LEVEL[d_perm_protection_level],
            }
            declared_permissions[d_perm_name] = d_perm_details
        # print(declared_permissions)
        all_permissions['uses_permission'] = uses_permission
        all_permissions['declared_permissions'] = declared_permissions
        return all_permissions

    def allow_backup(self):
        logging.info('get allow_backup')
        backup = self.__get_element_by_tag_and_attribute('application', 'allowBackup')
        if backup is None:
            return True
        else:
            if backup.lower() == 'true':
                return True
            else:
                return False

    def debuggable(self):
        logging.info("get attribute debuggable")
        debuggable = self.__get_element_by_tag_and_attribute('application', 'debuggable')
        if debuggable is None:
            return False
        else:
            if debuggable.lower() == 'true':
                return True
            else:
                return False

    def is_testonly(self):
        logging.info('get attribute testonly')
        test_only = self.__get_element_by_tag_and_attribute('application', 'testOnly')
        if test_only is None:
            return False
        else:
            if test_only.lower() == 'true':
                return True
            else:
                return False

    def get_export_assembly(self):
        logging.info("get export assembly")
        exported_assembly_dict = {}
        find_tags = ["activity", "activity-alias", "service", "receiver"]
        """
        对于activity,activity-alias,service,recevicer,如果设置exported = true则查看permission 是否为normal和dangerous。
        如果没设置exported，则查看intent-filter，如果有intenr-filter则exported默认为true，则转到查看permission
        """
        for tag in find_tags:
            export_list = []
            for item in self.__xml.getElementsByTagName(tag):
                exported = item.getAttributeNS(NS_ANDROID_URI, 'exported')
                permissions = item.getAttributeNS(NS_ANDROID_URI, 'permission')
                is_need_check_permission = False
                if exported == '':
                    filter = item.getElementsByTagName('intent-filter')
                    for filter_item in filter:
                        if len(filter_item.getElementsByTagName('action')) > 0:
                            is_need_check_permission = True
                            break
                elif exported.lower() == 'true':
                    is_need_check_permission = True
                if is_need_check_permission:
                    if permissions == '':
                        export_list.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
                    else:
                        all_declare_permission = self.get_all_permission()['declared_permissions']
                        declare_permissions = all_declare_permission.get(permissions, '')
                        if declare_permissions != '':
                            permissions_level = declare_permissions.get('protectionLevel')
                            if permissions_level == 'normal' or permissions_level == 'dangerous':
                                export_list.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
                        else:
                            export_list.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
            exported_assembly_dict[tag] = export_list

        """
        对于content provide,如果设置exported = true则查看permission 是否为normal和dangerous。
        如果没设置exported，则查看targetSdkVersion >= 17?，如果是则exported默认为false，否则则转到查看permission
        """
        export_provide_list = []
        target_sdk_version = self.__apk.get_target_sdk_version()
        mini_sdk_version = self.__apk.get_min_sdk_version()
        logging.info('target_sdk_version:' + str(target_sdk_version))
        logging.info('mini_sdk_version:' + str(mini_sdk_version))
        for item in self.__xml.getElementsByTagName('provider'):
            exported = item.getAttributeNS(NS_ANDROID_URI, 'exported')
            permissions = item.getAttributeNS(NS_ANDROID_URI, 'permission')
            read_permissions = item.getAttributeNS(NS_ANDROID_URI, 'readPermission')
            write_permissions = item.getAttributeNS(NS_ANDROID_URI, 'writePermission')
            check_permission_list = [permissions, read_permissions, write_permissions]
            is_need_check_permission = False
            if exported == '':
                if int(mini_sdk_version) < 17 or int(mini_sdk_version) < 17:
                    is_need_check_permission = True
            elif exported.lower() == 'true':
                is_need_check_permission = True
            if is_need_check_permission:
                if permissions == '' and read_permissions == '' and write_permissions == '':
                    export_provide_list.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
                else:
                    all_declare_permission = self.get_all_permission()['declared_permissions']
                    for per in check_permission_list:
                        if per != '':
                            declare_permissions = all_declare_permission.get(per, '')
                            if declare_permissions != '':
                                permissions_level = declare_permissions.get('protectionLevel')
                                if permissions_level == 'normal' or permissions_level == 'dangerous':
                                    export_provide_list.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
        exported_assembly_dict['provider'] = export_provide_list
        return exported_assembly_dict
# if item.getElementsByTagName("intent-filter"):
# 	elements.append(item.getAttributeNS(NS_ANDROID_URI, 'name'))
# else:
# 	pass
