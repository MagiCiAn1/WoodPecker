# coding:utf-8
"""
    @auth wangzhixiang
    @time 2019/3/15 12:02
"""
def get_interface_method_by_desc(dvm, implement_interface, method_and_descriptor_list):
	dict_result = {}
	for cls in dvm.get_classes():
		if is_class_implements_interface(cls, implement_interface) is True:
			class_name = cls.get_name()
			if class_name not in dict_result:
				dict_result[class_name] = []
			for method in cls.get_methods():
				method_and_desc = method.get_name() + method.get_descriptor()
				if method_and_desc in method_and_descriptor_list:
					dict_result[class_name].append(method)
	return dict_result

def is_class_implements_interface(cls, implement_interface):
	class_interface = cls.get_interfaces()
	if class_interface is None:
		return False
	for imp in implement_interface:
		if imp not in class_interface:
			return False
	return True


def check_have_override(class_and_methods_dict):
	not_override_list = []
	for class_name, methods in class_and_methods_dict.items():
		for method in methods:
			ins_count = 0
			for ins in method.get_instructions():
				ins_count = ins_count + 1
			if ins_count < 4:
				not_override_list.append(class_name+ method.get_name() + method.get_descriptor())
	return not_override_list

if __name__ == '__main__':
	pass