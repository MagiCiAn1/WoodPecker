import os
import zipfile
import platform


class Helper(object):
	@staticmethod
	def isNullOrEmptyString(input_string, strip_whitespaces=False):
		if input_string is None :
			return True
		if strip_whitespaces :
			if input_string.strip() == "" :
				return True
		else :
			if input_string == "" :
				return True
		return False

	@staticmethod
	def strip_string(value):
		if isinstance(value, basestring):
			return value[1:-1]  #strip the left and right '
		return value

	@staticmethod
	def unzip_file(apk_path,filename):

		if not zipfile.is_zipfile(apk_path):
			return None
		filepath = ''
		try :
			zfobj = zipfile.ZipFile(apk_path)
			oriname = filename

			if os.sep == '\\':
				filename = filename.replace('/', os.sep)
			dir_name = os.path.dirname(apk_path)
			content = zfobj.read(oriname)
			zfobj.close()
			file_base_name = os.path.basename(filename)
			filepath = os.path.join(dir_name, file_base_name)
			with open(filepath, 'wb') as file:
				file.write(content)
			return filepath
		except:
				Helper.delete_file(filename)
				return None
	@staticmethod
	def delete_file(file_name):
		if os.path.exists(file_name):
			os.remove(file_name)
	@staticmethod
	def platform_sys():
		return platform.system()
