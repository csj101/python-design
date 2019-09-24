#-*- coding:utf-8 -*- 



class Target(object):
	"""docstring for Target"""
	def request(self):
		print('普通请求！')

class Adaptee(object):
	"""docstring for Adaptee"""
	def special_request(self):
		print('特殊请求!')


class Adapter(Target):
	"""docstring for Adapter"""
	def __init__(self):
		super(Adapter, self).__init__()
		self.adaptee = Adaptee()

	def request(self):
		self.adaptee.special_request()

if __name__ == '__main__':
	
	adapter = Adapter()
	adapter.request()		
		
		

