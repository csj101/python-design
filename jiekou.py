#-*- coding:utf-8 -*-

from abc import ABCMeta,abstractmethod


class Payment(object):


	@abstractmethod		#定义抽象方法的关键字
	def pay():
		pass

class AiliPay(Payment):
	
	#子类继承接口,必须实现接口中定义的抽象方法,否则不能实例化对象
	def pay(self,money):
		print('使用支付宝支付%s元'%money)
		

class ApplePay(object):
	

	def pay(self,money):
		print('使用苹果支付%s元'%money)
		

if __name__ == '__main__':
	a = AiliPay()
	b = ApplePay()
	a.pay(10)
	b.pay(20)