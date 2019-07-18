#coding:utf-8

import re


class ApkDetect(object):
	def __init__(self, apk):
		self.__application_name = [r'com\.secneo\.apkwrapper|com\.secneo\.guard\.ApplicationWrapper|com\.secshell\.shellwrapper\.SecAppWrapper|com\.bangcle\.protect|com\.secshell\.secData\.ApplicationWrapper', r'com\.qihoo\.util\.StubApplication',
		                        r'com\.payegis\.ProxyApplication', r'com\.nqshield\.NqApplication', r'com\.tencent\.StubShell\.TxAppEntry',
		                        r'com\.ijiami\.residconfusion\.ConfusionApplication|com\.shell\.SuperApplication', r'com\.edog\.AppWrapper|com\.chaosvmp\.AppWrapper',
		                        r'com\.ali\.mobisecenhance\.StubApplication', r'com\.baidu\.protect\.StubApplication',r'com\.netease\.nis\.wrapper\.MyApplication']
		self.__so_name = [r'libDexHelper\S*\.so|libsecexe\S*\.so|libSecShell\.so', r'libjiagu\S*\.so|libprotectClass\S*\.so',
	               r'libegis\S*\.so|libegisboot\S*\.so|libegismain\S*\.so|libNSaferOnly\S*\.so', r'libnqshield\S*\.so',
	               r'libtxRes\S*\.so|libshell\S*\.so', r'libexecgame\.so|ijiami\S*.dat', r'lib\wdog\.so', r'libmobisec\w*\.so|libaliutils\S*\.so',
	               r'libbaiduprotect\S*\.so', r'libnesec\.so|assets/data\.db|assets/clazz\.jar|libdexfix\.so', r'libAPKProtect\S*\.so']
		self.__app_name_regex = [re.compile(self.__application_name[0], re.I), re.compile(self.__application_name[1], re.I),
	                      re.compile(self.__application_name[2], re.I), re.compile(self.__application_name[3], re.I),
	                      re.compile(self.__application_name[4], re.I), re.compile(self.__application_name[5], re.I),
	                      re.compile(self.__application_name[6], re.I), re.compile(self.__application_name[7], re.I),
	                      re.compile(self.__application_name[8], re.I), re.compile(self.__application_name[9], re.I)]
		self.__so_name_regex = [re.compile(self.__so_name[0], re.I), re.compile(self.__so_name[1], re.I), re.compile(self.__so_name[2], re.I),
	                     re.compile(self.__so_name[3], re.I), re.compile(self.__so_name[4], re.I), re.compile(self.__so_name[5], re.I),
	                     re.compile(self.__so_name[6], re.I), re.compile(self.__so_name[7], re.I), re.compile(self.__so_name[8], re.I),
	                     re.compile(self.__so_name[9], re.I), re.compile(self.__so_name[10], re.I)]
		self.__xml_string = str(apk.get_android_manifest_axml().get_xml())
		self.__apk = apk

	def check_by_xml(self):
		for index in range(0,len(self.__app_name_regex)):
			result = self.__app_name_regex[index].search(self.__xml_string)
			if result:
				return index+1
		return 0

	def check_by_so(self):
		for file_name in self.__apk.get_files():
			if file_name.endswith('.so'):
				for index in range(0,len(self.__so_name_regex)):
					result = self.__so_name_regex[index].search(file_name)
					if result:
						return index+1
		return 0

	@staticmethod
	def has_wrapped(apk):
		protectflag_dict = {1: "梆梆加固",2: "360加固", 3: "通付盾加固",
		                    4: "网秦加固", 5: "腾讯加固",6: "爱加密加固",
		                    7: "娜迦加固",8: "阿里加固", 9: "百度加固",
		                    10:"网易云加密",11: "APKProtect加固",0: "NO WRAPPER"}
		apk_detect = ApkDetect(apk)
		result = apk_detect.check_by_so()
		if result == apk_detect.check_by_xml():
			return protectflag_dict.get(result, 0)
