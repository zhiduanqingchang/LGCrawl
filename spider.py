#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/5/16 14:03
# @Author  : ChenHuan
# @Site    : 
# @File    : spider.py
# @Desc    :
# @Software: PyCharm

import hashlib
import os
import requests
import time
import subprocess
import sys
import json
from bs4 import BeautifulSoup

class lagou_login(object):
    """
    模拟登录拉勾网
    """
    # __init_-用来对实例的属性进行初使化
    def __init__(self):
        # 请求对象 session： 创建持久对话
        self.session = requests.session()
        # CaptchaImagePath：验证码的path
        # os.path.split(path) 将路径名path拆分为一个元组对(head,tail),其中tail是路径名的最后一个部分,head是前面的所有内容.
        # os.path.relpath(path, start=os.curdir) 返回自当前目录或者可选的start目录的path相对文件路径
        # os.sep 操作系统用来分隔路径名组件的字符
        self.CaptchaImagePath = os.path.split(os.path.realpath(__file__))[0] + os.sep + 'captcha.jpg'
        # User-Agent 含义:用于伪装成浏览器身份请求网页.它的意思自然就是表示浏览器的身份,说明是用的哪种浏览器进行的操作
        # Referer 含义:(这个也是爬虫常用到的，防盗链)客户端通过当前URL代表的页面出发访问我们请求的页面.爬虫中,一般我们只要把它设置成请求的网页链接就好了
        # X - Requested - With请求头用于在服务器端判断request来自Ajax请求还是传统请求
        # 如果X-Requested-With的值为 XMLHttpRequest,则为 Ajax 异步请求. 为 null 则为传统同步请求.
        self.headers = {
            'Referer' : 'http://passport.lagou.com/login/login.html',
            'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36',
            'X-Requested-With' : 'XMLHttpRequest',
        }

    def encryptPwd(self, password):
        """
        登录密码加密
        :param password:
        :return:
        """
        # Python的hashlib提供了常见的摘要算法,如MD5,SHA1等等.
        # 什么是摘要算法呢？摘要算法又称哈希算法、散列算法.它通过一个函数,把任意长度的数据转换为一个长度固定的数据串（通常用16进制的字符串表示）.
        # 此处对密码进行了md5双重加密
        # MD5的全称是Message-Digest Algorithm 5（信息-摘要算法）.
        # 128位长度,目前MD5是一种不可逆算法.具有很高的安全性.它对应任何字符串都可以加密成一段唯一的固定长度的代码.
        password = hashlib.md5(password.encode('utf-8')).hexdigest()
        # 源码中拉勾网对密码的处理:
        # 首先对密码进行一次md5加密,然后前后加上veenike,最后再次进行md5加密
        # var a, F = e, c = F.parent.collectData(), g = "veenike";
        # c.isValidate && (c.password = md5(c.password),
        # c.password = md5(g + c.password + g),
        password = 'veenike' + password + 'veenike'
        password = hashlib.md5(password.encode('utf-8')).hexdigest()
        return password

    def getTokenCode(self):
        """
        获取请求token
        :return:
        """
        login_page = 'https://passport.lagou.com/login/login.html'
        data = self.session.get(login_page, headers = self.headers).content
        # 传入from_encoding参数来指定编码方式
        soup = BeautifulSoup(data, 'lxml', from_encoding='utf-8')
        # 在请求头部中会发现存在这两个参数:
        # X - Anit - Forge - Code,X - Anit - Forge - Token
        # 在源码中可以看到:
        # < / script >
        # < !-- 页面样式 --> < !-- 动态token，防御伪造请求，重复提交 -->
        # < script >
        # window.X_Anti_Forge_Token = '843cfcea-7285-4231-acb6-f6504b292603';
        # window.X_Anti_Forge_Code = '98325002';
        # < / script >
        # 所以要从登录页面提取Token,Code.并在头信息里面添加.
        anti_token = {'X-Anit-Forge-Token': 'None', 'X-Anit-Forge-Code': '0'}
        # str.splitlines([keepends]) 按照行('\r', '\r\n', \n')分隔,返回一个包含各行作为元素的列表.
        # keepends -- 在输出结果里是否去掉换行符('\r', '\r\n', \n'),默认为 False,不包含换行符,如果为 True,则保留换行符.
        token_code = soup.findAll('script')[1].getText().splitlines()
        # str.split(str="", num=string.count(str)) 通过指定分隔符对字符串进行切片,如果参数 num 有指定值,则仅分隔 num 个子字符串
        # str -- 分隔符，默认为所有的空字符，包括空格、换行(\n)、制表符(\t)等; num -- 分割次数
        # str.strip([chars]) 方法用于移除字符串头尾指定的字符（默认为空格）,返回移除字符串头尾指定的字符生成的新字符串
        # chars -- 移除字符串头尾指定的字符
        anti_token['X-Anit-Forge-Token'], anti_token['X-Anit-Forge-Code'] = map(
            lambda x : x.split('= \'')[1].strip('\';'),token_code[1:]
        )
        return anti_token

    def getCapdcha(self):
        """
        人工读取验证码并返回
        :return:
        """
        captchaImgUrl = 'https://passport.lagou.com/vcode/create?from=register&refresh=%s' % time.time()
        captchaImg = self.session.get(captchaImgUrl, headers=self.headers).content

        # 写入验证码图片
        with open(self.CaptchaImagePath, 'wb') as f:
            f.write(captchaImg)

        # 打开验证码图片
        # platform模块提供了有关系统身份的详细检查
        # subprocess模块允许你生成新进程，连接到其输入/输出/错误管道，并获取其返回码
        # subprocess.run(args, *, stdin=None, input=None, stdout=None, stderr=None, shell=False, timeout=None, check=False)
        # 运行args描述的命令
        # os.startfile(path[, operation]) 用相关的应用程序启动一个文件.
        if sys.platform.find('darwin') >= 0:
            subprocess.run(['open', self.CaptchaImagePath])
        elif sys.platform.find('linux') >= 0:
            subprocess.run(['xdg-open', self.CaptchaImagePath])
        else:
            os.startfile(self.CaptchaImagePath)

        # 输入返回验证码
        captcha = input("请输入当前验证码%s: " % self.CaptchaImagePath)
        print('你输入的验证码是:% s' % captcha)
        return captcha

    def login(self, username, password, captcha = None, token_code = None):
        """
        登陆操作
        :return:
        """
        login_url = 'https://passport.lagou.com/login/login.json'
        data = {
            'isValidate' : 'true',
            'username' : username,
            'password' : password,
            'request_form_verifyCode' : (captcha if captcha != None else ''),
            'submit' : '',
        }

        # 向头信息里添加Token,Code
        # copy 浅拷贝构建一个新的复合对象,然后（尽可能地）将原始对象中引用插入到新对象中
        headers = self.headers.copy()
        token_code = self.getTokenCode() if token_code is None else token_code
        # dict.update(dict2)函数把字典dict2的键/值对更新到dict里
        # dict2 -- 添加到指定字典dict里的字典
        headers.update(token_code)

        response = self.session.post(login_url, data = data, headers = headers)
        # json.dumps	将 Python 对象编码成 JSON 字符串
        # json.loads	将已编码的 JSON 字符串解码为 Python 对象
        data = json.loads(response.content.decode('utf-8'))
        # data = {"content":{"rows":[]},"message":"操作过于频繁，请刷新页面后再试,错误码10011","state":10011}
        # data = {"content":{"rows":[]},"message":"该帐号不存在或密码错误，请重新输入","state":400}
        # data = {"content":{"rows":[]},"message":"验证码错误，请填写正确的验证码！","state":10010}
        if data['state'] == 1:
            return response.content
        elif data['state'] == 10010:
            print(data['message'])
            captcha = self.getCapdcha()
            token_code = {'X-Anit-Forge-Code' : data['submitCode'], 'X-Anit-Forge-Token' : data['submitToken']}
            return self.login(username, password, captcha, token_code)
        else:
            print(data['message'])
            return False

if __name__ == '__main__':
    username = input('请输入常用手机号/邮箱: ')
    password = input('请输入密码: ')

    lagou = lagou_login()
    password = lagou.encryptPwd(password)

    data = lagou.login(username, password)
    if data:
        print(data)
        print('登录成功')
    else:
        print('登录不成功')