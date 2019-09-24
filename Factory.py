#-*- coding:utf-8 -*- 



class Person(object):
	"""docstring for Person"""
	def __init__(self):
		super(Person, self).__init__()
		self.name = name
		self.gender = gender

	def get_name(self):
		return self.name

	def get_gender(self):
		return self.gender



class Male(Person):
	"""docstring for Male"""
	def __init__(self, name):
		print( 'Hello Mr.' + name)

class Female(Person):
	"""docstring for Female"""
	def __init__(self, name):
		print( 'Hello Miss. ' + name)


class Factory:
	"""docstring for Factory"""
	def get_Person(self,name,gender):
		if gender == 'M':
			return Male(name)

		if gender == 'F':
			return Female(name)


if __name__ == '__main__':
	factory = Factory()
	Person = factory.get_Person('wang','F')
		
		