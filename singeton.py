#-*- coding:utf-8 -*-

from abc import ABCMeta,abstractmethod

class Singeton(object):
	"""docstring for Singeton"""
	def __new__(cls,*args,**kwargs):
		if not hasattr(cls,'_instance'):
			cls._instance = super(Singeton,cls).__new__(cls)

		return cls._instance
		

class putong(object):
	"""docstring for putong"""
	def __init__(self):
		super(putong, self).__init__()
		
		


if __name__ == '__main__':
	s1 = Singeton()
	s2 = Singeton()
	print(s1)
	print(s2)

	s3 = putong()
	print(s3)
	s4 = putong()
	print(s4)
