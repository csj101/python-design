#-*- coding:utf-8 -*-


import re
import json 
from splinter.browser import Browser
import time 
import sys
import httplib2
from urllib import parse,request
import smtplib
from http import cookiejar
from email.mime.text import MIMEText
from prettytable import PrettyTable
 

class BrushTicket():
	"""docstring for BrushTicket"""
	def __init__(self, username,password):
		super(BrushTicket, self).__init__()
		self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36'}
		self.opener = self.__get_opener()
		self.username = username
		self.password = password
		self.receive_email = 'chenshiju0626@163.com'
		self.seatType = '1'
		self.seat_types_code = ["M","0","1","N","2","3","4","F","6","9"]
		self.ticketType = '1'
		self.query_seats_count = 1
		self.passengers_name = ''
		self.ticketTypes = {"1":"成人票","2":"儿童票","3":"学生票","4":"残军票"}
		self.seatTypes = {
			"M":"一等座",
			"0":"二等座",
			"1":"硬座",
			"N":"无座",
			"2":"软座",
			"3":"硬卧",
			"4":"软卧",
			"F":"动卧",
			"6":"高等软卧",
			"9":"商务座",
			}

		self.seat_dict = {
			'yz_num':'硬座',
			'wz_num':'无座',
			'rz_num':'软座',
			'yw_num':'硬卧',
			'rw_num':'软卧',
			'dw_num':'动卧',
			'gr_num':'高级软卧',
			'ze_num':'二等座',
			'zy_num':'一等座',
			'swz_num':'商务座',
		}

	def __get_opener(self):
		c = cookiejar.LWPCookiejar()
		cookie = request.HTTPCookieProcessor(c)
		opener = request.build_opener(cookie)
		request.install_opener(opener)
		return opener


	def get_req_result(self,url,data):
		
		if data == None:
			req = request.Request(url)
			req.headers = self.headers
			result = self.opener.open(req).read().decode()

			return result
		else:
			req = request.Request(url)
			req.headers = self.headers

			datas = parse.urlencode(data).encode()

			result = self.opener.open(req,data = data).read().decode()

			return result


	def get_image(self):
		req_catch_image = request.Request('https://kyfw.12306.cn/passport/captcha/captcha-image')

		req_catch_image.headers = self.headers
		code_file = self.opener.open(req_catch_image).read()

		with open('/code.jpg','wb') as f:
			f.wirte(code_file)


	def verify(self):
		answer = {
			"1":"40,40",
			"2":"110,40",
			"3":"180,40",
			"4":"260,40",
			"5":"40,120",
			"6":"110,120",
			"7":"180,120",
			"8":"260,120"
		}

		print("+----------+----------+----------+----------+")
		print("|    1     |    2     |    3     |    4     |")
		print("|----------|----------|----------|----------|")
		print("|    5     |    6     |    7     |    8     |")
		print("+----------+----------+----------+----------+")

		input_code = input("请在1—8中选择输入验证图片编号，以半角','隔开。(例如：1,3,5):")

		answer_code = ""

		try:
			for i in input_code.split(','):
				if i is not input_code[0]:
					answer_code += ','+ answer[i] 
				else:
					answer_code += answer[i]
		except:
			print('请重新输入')
			self.verify()

		#进行图片验证
		verify_url = 'https://kyfw.12306.cn/passport/captcha/captcha-check'
		

		data = {
			'answer':answer_code,
			'login_size':'E',
			'rand':'sjrand'
		}

		
		check_result = self.get_req_result(verify_url,data)

		return check_result


	def sys_verify(self):
		self.get_image()
		verify_result = self.verify()
		while verify_result['result_code'] is not '4':
			print('验证失败，已重新下载图片，请重新验证！')
			self.get_image()
			verify_result = self.verify()

		print('验证通过！')
		return 


	def login(self):
		login_url = 'https://kyfw.12306.cn/passport/web/login'
		data = {
			'username':self.username,
			'password':self.password,
			'appid':'otn'
		}


		login_result = self.get_req_result(login_url,data)

		return json.loads(login_result)



	def get_tk(self):
		get_tk_url = 'https://kyfw.12306.cn/passport/web/auth/uamtk'
		data = {"appid":"otn"}

		result = self.get_req_result(get_tk_url,data)

		return json.loads(result)


	def auth(self,newapptk):
		
		auth_url = 'https://kyfw.12306.cn/otn/uamauthclient'
		data = {'tk':newapptk}


		result = self.get_req_result(auth_url,data)

		return json.loads(result)


	def sys_login(self):
		self.login()

		result = self.get_tk()

		try:
			result = self.auth(result['newapptk'])
		except:
			print("登录失败,账号或密码错误!")
			self.sys_verify()
			self.sys_login()

		pritn('登录成功')

		return




	#获得所有站点信息和名字模块


	def  get_city_result(self):
		url = 'https://kyfw.12306.cn/otn/resources/js/framework/station_name.js?station_version=1.9093'
		data = None

		result = self.get_req_result(url,data)

		return result


	def get_city_code(self,name):
		
		result = self.get_city_result()

		start = result.index(name) + len(name)
		result = result[start+1 : start+4]
		return result


	def get_station_names(self):
		
		result = self.get_city_result()
		stations = re.findall(r'([\u4e00-\u9fa5]+)\|([A-Z]+)',result)
		station_codes = dict(stations)
		station_name = dict(zip(station_codes.values(), station_codes.keys())) 

		return station_name



	#获取余票模块

	def get_tickets(self,from_station,to_station,train_date):
		
		url = 'https://kyfw.12306.cn/otn/leftTicket/queryX?'

		data = {
			'leftTicketDTO.train_date':train_date,
			'leftTicketDTO.from_station':from_station,
			'leftTicketDTO.to_station':to_station,
			'purpose_codes':"ADULT"
		}


		result = self.get_req_result(url,data)

		print(result)

		return json.loads(result)


	def get_ticket_format(self,from_station_name,from_station,to_station_name,to_station,train_date):
		
		print('为您查询到从', from_station_name, '到', to_station_name, '的余票信息如下：')
		result = self.get_tickets(from_station,to_station,train_date)

		result_list = result['data']['result']

		stations_name = self.get_station_names()
		table = PrettyTable(
				["车次", "出发/到达车站", "出发/到达时间", "历时", "商务座", "一等座", "二等座", "高级软卧", "软卧", "动卧", "硬卧", "软座", "硬座", "无座", "其他","备注"]
			)
		for item in result_list:
			name = [
				'station_train_code',
				'from_station_name',
				'start_time',
				'lishi',
				'swz_num',
				'zy_num',
				'ze_num',
				'gr_num',
				'rw_num',
				'dw_num',
				'yw_num',
				'rz_num',
				'yz_num',
				'wz_num',
				'qt_num',
				'note_num'
			]

			data ={
				'station_train_code':'',
				'from_station_name':'',
				'to_station_name':'',
				'start_time':'',
				'end':'',
				'lishi':'',
				'swz_num':'',
				'zy_num':'',
				'ze_num':'',
				'dw_num':'',
				'gr_num':'',
				'rw_num':'',
				'yw_num':'',
				'rz_num':'',
				'yz_num':'',
				'wz_num':'',
				'qt_num':'',
				'note_num':''
			}

			item = item.split('|')
			data['station_train_code'] = item[3] #车次在3号位
			data['from_station_name'] = item[6]  #始发站信息在6号位
			data['to_station_name'] = item[7]    #终点站信息在7号位
			data['start_time'] = item[8]         #出发时间信息在8号位
			data['arrive_time'] = item[9]        #抵达时间在9号位
			data['lishi'] = item[10]             #经历时间在10号位
			data['swz_num'] = item[32] or item[25]#商务座在32或25位
			data['zy_num'] = item[31]  			 #一等座信息在31号位
			data['ze_num'] = item[30]			 #二等座信息在30号位
			data['gr_num'] = item[21] 			 #高级软卧在21号位
			data['rw_num'] = item[23]			 #软卧信息在23号位
			data['dw_num'] = item[27]            #动卧信息在27号位
			data['yw_num'] = item[28] 			 #硬卧信息在28号位
			data['rz_num'] = item[24]  			 #软座信息在24号位
			data['yz_num'] = item[29]			 #硬座信息在29号位
			data['wz_num'] = item[26] 			 #无座信息在26号位
			data['qt_num'] = item[22]			 #其他信息在22号位
			data['note_num'] = item[1]			 #备注信息在1号位

			for pos in name:
				if data[pos] == '':
					data[pos] = '-'


			tickets = []

			tickets.append(data)

		for ticket in tickets:
			table.add_row(ticket)

		print(table)


	def get_secret_str(self,from_station,to_station,train_date):
		secret_str = {}
		result = self.get_tickets(from_station,to_station,train_date)
		result = result['data']['result']

		for item in result:
			msg = item.split('|')
			secret_str[msg[3]] = parse.unquote(mag[0])

		return secret_str



	def get_seats(self,station_train_code,from_station,to_station,train_date):
		seats = {}
		result = self.get_tickets(from_station,to_station,train_date)
		result = result['data']['result']

		for item in result:
			item =item.split('|')
			if item[3] == station_train_code:
				seats['swz_num'] = item[32] or item[25]   #商务座在32或25位置
				seats['zy_num'] = item[31]   	#一等座信息在31号位置
				seats['ze_num'] = item[30]   	#二等座信息在30号位置
				seats['gr_num'] = item[21] 		#高级软卧信息在21号位置
				seats['rw_num'] = item[23]		#软卧信息在23号位置
				seats['dw_num'] = item[27]		#动卧信息在27号位置
				seats['yw_num'] = item[28]		#硬卧信息在28号位置
				seats['rz_num'] = item[24]		#软座信息在24号位置
				seats['yz_num'] = item[29]		#硬座信息在29号位置
				seats['wz_num'] = item[26]		#无座信息在26号位置

		return seats


	def selet_order_details(self):
		
		print("座位码对照表：")
		print("-----------------------")
		print("|  序号 |  座位类型   |")
		print("|   M   |   一等座    |")
		print("|   0   |   二等座    |")
		print("|   1   |    硬座     |")
		print("|   N   |    无座     |")
		print("|   2   |    软座     |")
		print("|   3   |    硬卧     |")
		print("|   4   |    软卧     |")
		print("|   F   |    动卧     |")
		print("|   6   |  高级软卧   |")
		print("|   9   |   商务座    |")
		print("-----------------------")

		seatType = input('请选择车座类型，enter键默认硬座（例如：1）:')
		if seatType == '':
			self.seatType = '1'
		elif seatType in self.seat_types_code:
			self.seatType = seatType

		else:
			raise Exception('没有对应的车座类型！')


		print("车票类型对照表：")
		print("-----------------------")
		print("|  序号 |  座位类型  |")
		print("|   1   |   成人票   |")
		print("|   2   |   儿童票   |")
		print("|   3   |   学生票   |")
		print("|   4   |   残军票   |")
		print("-----------------------")
		
		ticketType = input("请选择车票类型，enter键默认成人票（例如：1）:")	
		self.ticketType = ticketType if ticketType != '' else "1"

		passengers_name = input("请输入乘车人姓名，如有多人，请以英文','隔开（例如：晏沈威,晏文艳）：")

		self.passengers_name = passengers_name if passengers_name != None else'陈士举'

		email = input("请输入发送提醒的邮箱（例如：chenshiju0626@163.com）：")
		self.receive_email = email if email != None else 'chenshiju0626@163.com'



	def query_ticket(self,seats,seat_msg):
		
		if seats[seat_msg] == None or seats[seat_msg] == '无':
			pritn("无",self.seat_dict[seat_msg],"座位！")
			return False

		else:
			print("查询到",seats[seat_msg], self.seat_dict[seat_msg], "座位！")
			return True




	def sys_seek_tickets(self):
		while True:
			from_station_name = '石家庄'
			from_station_name = input('请输入出发站，如石家庄：')

			to_station_name = '北京西'
			to_station_name = input('请输入到达站，如北京西:')

			train_date = '2019-02-28'
			train_date = input('请输入乘坐日期，如2019-02-28')

			print('正在查询余票，请稍等')

			from_station = self.get_city_code(from_station_name)
			to_station = self.get_city_code(to_station_name)

			self.get_ticket_format(from_station_name,from_station,to_station_name,to_station,train_date)

			if input("输入'1'可继续查询,输入enter键选择车次！") != 1:
				break

			station_train_code = 'K464'
			station_train_code = input("请输入乘车车次(例：K464):")

			self.selet_order_details()

			while True:
				seats = self.get_seats(station_train_code,from_station,to_station,train_date)
				print('第{}次查票！'.format(self.query_seats_count),seats)

				if (self.seatType == '1'):
					if self.query_ticket(seats,'yz_num') == True:break
				elif(self.seatType == 'N'):
					if self.query_ticket(seats,'wz_num') == True:break
				elif(self.seatType == '2'):
					if self.query_ticket(seats,'rz_num') == True:break
				elif(self.seatType == '3'):
					if self.query_ticket(seats,'yw_num') == True:break
				elif(self.seatType == '4'):
					if self.query_ticket(seats,'rw_num') == True:break
				elif(self.seatType == '6'):
					if self.query_ticket(seats,'gr_num') == True:break
				elif(self.seatType == '0'):
					if self.query_ticket(seats,'ze_num') == True:break
				elif(self.seatType == 'M'):
					if self.query_ticket(seats,'zy_num') == True:break
				elif(self.seatType == 'F'):
					if self.query_ticket(seats,'dw_num') == True:break
				elif(self.seatType == '9'):
					if self.query_ticket(seats,'swz_num') == True:break
				else:
					raise Exception('没有相应车次！')
					break

				self.query_seats_count += 1
				time.sleep(2)

			secret_str = self.get_secret_str(from_station,to_station,train_date)[station_train_code]

			result = {}
			result['from_station'] = from_station
			result['to_station'] = to_station
			result['train_date'] = train_date
			result['secret_str'] = secret_str
			return result







	#订单模块
	def get_train_number(self,tickets):
		
		secret_str = parse.unquote(tickets['secret_str'])
		from_station = tickets['from_station']
		to_station = tickets['to_station']
		train_date = tickets['train_date']
		url = 'https://kyfw.12306.cn/otn/leftTicket/submitOrderRequest'

		data = {
			'secretStr':secret_str,
			'train_date':train_date,
			'back_train_date':'',
			'tour_flag':'dc',
			'purpose_codes':'ADULT',
			'query_from_station_name':from_station,
			'query_to_station_name':to_station,
			'undefined':''

		}


		result = self.get_req_result(url,data)

		return json.loads(result)






	def get_train_number_msg(self):
		
		url = 'https://kyfw.12306.cn/otn/confirmPassenger/initDc'
		data = {'_json_att':''}

		result = get_req_result(url,data)

		try:
			ticketInfoForPassengerForm = re.findall("var ticketInfoForPassengerForm = (.*?);",result)[0].replace("'",'"')
			globalRepeatSubmitToken = re.findall("globalRepeatSubmitToken = '(.*?)'",result)[0]
			key_check_isChange = re.findall("'key_check_isChange':'(.*?)'",result)[0]
		except:
			raise Exception('没有获取到车次信息！')

		ticketInfoForPassengerForm = json.loads(ticketInfoForPassengerForm)
		leftDetails = ticketInfoForPassengerForm['leftDetails']
		leftTicketStr = ticketInfoForPassengerForm['leftTicketStr']
		purpose_codes = ticketInfoForPassengerForm['queryLeftTicketRequestDTO']['purpose_codes']
		train_location = ticketInfoForPassengerForm['train_location']
		print('该车次剩余车票详情如下：')

		for item in leftDetails:
			print('\t',item)

		msg_order_finally_submit = {}
		msg_order_finally_submit['purpose_codes'] = purpose_codes
		msg_order_finally_submit['key_check_isChange'] = key_check_isChange
		msg_order_finally_submit['leftTicketStr'] = leftTicketStr
		msg_order_finally_submit['train_location'] = train_location
		msg_order_finally_submit['token'] = globalRepeatSubmitToken

		return msg_order_finally_submit


	def select_passenger(self,passengers):
		
		ps = self.passengers_name

		oldPassengerStr = ''
		passengerTicketStr = ''

		seatType = 1 if self.seatType == 'N' else seatType

		try:
			ps = ps.split(',')
			for p in ps:
				oldPassengerStr +=  passengers[p]['passenger_name'] + ',' +\
									passengers[p]['passenger_id_type_code'] + ','+\
									passengers[p]['passenger_id_no'] + ','+\
									passengers[p]['passenger_type']+ '_'

				ticketStr = "{},{},{},{},{},{},{},N".format(
						seatType,
						passengers[p]['passenger_flag'],
						self.ticketType,
						passengers[p]['passenger_name'],
						passengers[p]['passenger_id_type_code'],
						passengers[p]['passenger_id_no'],
						passengers[p]['mobile_no']
					)

				passengerTicketStr += ticketStr + '_'if p != ps[len(ps)-1] else ticketStr

		except:
			print('输入信息有误！')

		result = {}
		result['oldPassengerStr'] = oldPassengerStr
		result['passengerTicketStr'] = passengerTicketStr

		return result



	def order_submit(seatType,msg_passenger,token):
		
		url = 'https://kyfw.12306.cn/otn/confirmPassenger/checkOrderInfo'
		data = {
			'cancel_flag':'2',
			'bed_level_order_num':'000000000000000000000000000000',
			'passengerTicketStr':msg_passenger['passengerTicketStr'],
			'oldPassengerStr':msg_passenger['oldPassengerStr'],
			'tour_flag':'dc',
			'randCode':'',
			'whatsSelect':'1',
			'_json_att':'',
			'REPEAT_SUBMIT_TOKEN':token
		}

		result = self.get_req_result(url,data)

		return json.loads(result)

	def order_ensure(seatType,msg_passenger,train_number_msg):

		purpose_codes = train_number_msg['purpose_codes']
		key_check_isChange = train_number_msg['key_check_isChange']
		leftTicketStr = train_number_msg['leftTicketStr']
		train_location = train_number_msg['train_location']
		token = train_number_msg['token']

		url = 'https://kyfw.12306.cn/otn/confirmPassenger/confirmSingleForQueue'

		data = {
			"passengerTicketStr": msg_passenger["passengerTicketStr"],
			"oldPassengerStr": msg_passenger["oldPassengerStr"],
			"randCode": "",
			"purpose_codes": purpose_codes,
			"key_check_isChange": key_check_isChange,
			"leftTicketStr": leftTicketStr,
			"train_location": train_location,
			"choose_seats": "",
			"seatDetailType": "000",
			"whatsSelect": "1",
			"roomType": "00",
			"dwAll": "N",
			"_json_att": "",
			"REPEAT_SUBMIT_TOKEN": token
		}

		result = self.get_req_result(url,data)

		return json.loads(result)


	def send_email(self):
		
		mail_host = 'smtp.163.com'
		mail_user = 'chenshiju0626@163.com'
		mail_pass = 'chenshiju1226'

		sender = 'chenshiju0626@163.com'

		receiver = 'chenshiju0626@163.com'

		message = MIMEText('席位已锁定，快去支付！')
		message['Form'] = sender
		message['To'] = receiver
		message['Subject'] = 'Python 12306 抢票'

		try:
			server = smtplib.SMTP()
			server.connect(mail_host)
			server.login(mail_user,mail_pass)
			server.sendmail(sender,receiver,message.as_string())
			server.close()
			print("邮件发送成功，已提醒用户",receiver,"付款!")
		except Exception as e:
			print('邮件发送失败！',e)


	def sys_order(self,tickets):
		#注入起始点、日期，车次码信息
		result = self.get_train_number(tickets)

		if result['status'] == True:
			print('查询车次信息成功')

		#获取车次的详细信息
		train_number_msg = seatType.get_train_number_msg()

		msg_passenger = self.passenger_name

		result = self.order_submit(msg_passenger,train_number_msg['token'])
		if result['status'] == True:
			print('检查订单信息正确，即将确认下单！')
			print(ime.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))

		result = self.order_ensure(msg_passenger,train_number_msg)
		if result['status'] == True:
			print('下单成功请尽快付款')
			print(ime.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())))

		self.sendmail()




	def run(self):
		#验证码
		self.sys_verify()
		#登录
		self.sys_login()
		#获取余票信息
		tickets = self.sys_seek_tickets()
		#下订单
		self.sys_order(tickets)



if __name__ == '__main__':
	username = '1013482460@qq.com'
	password = 'chenwang1226'

	train = BrushTicket(username,password)
	while True:
		train.run()






