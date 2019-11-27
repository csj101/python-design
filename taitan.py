# -*- coding:utf-8 -*-

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

import time



import warnings
warnings.filterwarnings("ignore")


def read(path):
	data = pd.read_csv(path)

	return data


def bili(data):
	sns.set()
	sns.set_style("ticks")
	plt.axis('equal')
	data['Survived'].value_counts().plot.pie(autopct='%1.2f%%')



if __name__ == '__main__':
	cvs_path = 'C:\\Users\\TMI\\Desktop\\python特性\\数据分析\\泰坦尼克\\train.csv'
	train_data = read(cvs_path)
	bili(train_data)







