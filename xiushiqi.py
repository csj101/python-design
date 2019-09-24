#-*- coding:utf-8 -*- 

import functools

def memoize(func):
	
	known = dict()

	@functools.wraps(func)
	def memoizer(*args):
		if args not in known:
			known[args] = func(*args)
			print(known[args])
		return known[args]
	return memoizer


#@memoize
def nums(n):
	
	assert(n >= 0)
	return 0 if n == 0 else n+nums(n-1)


if __name__ == '__main__':
	num = 10
	print(nums(num))



