#-*- coding:utf-8 -*- 

from abc import ABCMeta,abstractmethod

class Builder():
	
	__metaclass__ = ABCMeta

	@abstractmethod
	def draw_left_arm(self):
		pass

	@abstractmethod
	def draw_right_arm(self):
		pass

	@abstractmethod
	def draw_left_foot(self):
		pass

	@abstractmethod
	def draw_right_foot(self):
		pass


	@abstractmethod
	def draw_body(self):
		pass

class Fat(Builder):
	
	def draw_left_arm(self):
		print('画左胳膊')

	def draw_right_arm(self):
		print('画右胳膊')

	def draw_left_foot(self):
		print('画左脚，叫兽')

	def draw_right_foot(self):
		print('右脚残缺')

	def draw_body(self):
		print('身体肥胖')

class Thin(object):
	
	def draw_left_arm(self):
		print('左胳膊残缺')

	def draw_right_arm(self):
		print('画右胳膊')

	def draw_left_foot(self):
		print('画左脚，叫兽')

	def draw_right_foot(self):
		print('画右脚')

	def draw_body(self):
		print('身体消瘦')
		

class Director():
	
	def __init__(self,Person):
		self.Person = Person

	def draw(self):
		self.Person.draw_left_arm()
		self.Person.draw_right_arm()
		self.Person.draw_left_foot()
		self.Person.draw_right_foot()
		self.Person.draw_body()


if __name__ == '__main__':
	
	thin = Thin()
	fat = Fat()

	director_fat = Director(fat)
	director_fat.draw()

	director_thin = Director(thin)
	director_thin.draw()



		


