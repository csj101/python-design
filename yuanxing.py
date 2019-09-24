#-*- coding:utf-8 -*- 

import copy



class Point(object):
	"""docstring for Point"""
	def __init__(self, x,y):
		super(Point, self).__init__()
		self.x = x
		self.y = y



if __name__ == '__main__':
	point1 = Point(1,2)

	ponit2 = copy.copy(point1)
	ponit2.x = 3
	print(point1)
	print(ponit2)


	ponit2 = copy.deepcopy(point1)
	ponit2.x = 4
	print(point1)
	print(ponit2)


