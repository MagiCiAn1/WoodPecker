# coding:utf-8
"""
    @auth magician
    @time 2019/1/17 17:13
"""


class Stack(object):
	def __init__(self):
		self.__stack = []
		self.__len = 0

	def push(self, value):
		self.__stack.append(value)
		self.__len = self.__len + 1

	def get(self, index):
		return self.__stack[self.__len - index -1]

	def pop(self):
		if len(self.__stack) > 0:
			self.__stack.pop()
			self.__len = self.__len - 1

	def length(self):
		return self.__len


class InstructionAnalyze(object):
	def __init__(self, path, dvm, max_trace= -1):
		self.__path = path
		self.__stack = Stack()
		self.__dvm = dvm
		self.__max_trace = max_trace
		self.__src_dst = ''


	def get_stack(self):
		return self.__stack

	def get_src_dst(self):
		return self.__src_dst

	def analyze_pathp_inner_method(self, extra_offset=0):
		cm = self.__dvm.get_class_manager()
		src_class_name, src_method_name, src_descriptor = self.__path.get_src(cm)
		self.__src_dst = [src_class_name, src_method_name, src_descriptor]
		for cls in self.__dvm.get_classes():
			if cls.get_name() == src_class_name:
				for m in cls.get_methods():
					if m.get_name() == src_method_name and m.get_descriptor() == src_descriptor:
						trace = 0
						# print(m.show())
						for i in m.get_instructions():
							if self.__max_trace != -1:
								self.__load_instruction(i.get_op_value(), i.get_operands())
								trace += i.get_length()
								if trace > self.__max_trace:
									if extra_offset <= 0:
										break
									else:
										extra_offset -= 1
							else:
								self.__load_instruction(i.get_op_value(), i.get_operands())

	def analyze_method(self, extra_offset=0):
		trace = 0
		self.__src_dst = self.__path.get_class_name() + '->' + self.__path.get_name() + self.__path.get_descriptor()
		for i in self.__path.get_instructions():  ##path 为method
			if self.__max_trace != -1:
				self.__load_instruction(i.get_op_value(), i.get_operands())
				trace += i.get_length()
				if trace > self.__max_trace:
					if extra_offset <= 0:
						break
					else:
						extra_offset -= 1
			else:
				self.__load_instruction(i.get_op_value(), i.get_operands())

	def __load_instruction(self, ins, reg_list):
		self.__stack.push([ins, reg_list])


if __name__ == '__main__':
	stack = Stack()
	stack.push('123')
	stack.push('456')
	print stack.get(0)