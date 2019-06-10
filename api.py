import requests
import binascii
import json
import threading
import time
import logging
import socket
import queue

class Wechat(object):
    """
    微信类
    整体流程：1.创建token 2.获取二维码 3.获取扫码状态 4.账号密码包登录微信 5.tcp链接
    """

    def __init__(self, new_wx=True):  # threadID, name, counter
        """
        :type new_wx:# 为true时是新微信登录
        """
        self.heartbeat_bytes = [59, 154, 202, 238]  # 心跳反馈
        self.info_bytes = [0, 0, 0, 24]  # 服务器通知
        self.tcpClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.token = ''  # vv服务器使用的token 作用：识别操作的微信账号
        self.api = 'http://222.186.56.112:8001/'  # vv服务器地址
        self.new_wx = new_wx
        self.queue = queue.Queue
        logging.basicConfig(level=logging.INFO)

    def run(self):
        logging.info('微信类启用！')
        if self.new_wx:
            self.creat_wx_token()
            self.qr_login()
        else:
            self.two_login()

    def hex2bin(self, hex):
        """
        hex 转 bin
        :param hex:
        :return: bin
        """
        return binascii.a2b_hex(hex)

    def bin2hex(self, bin):
        """
        bin 转 hex
        :param bin:a
        :return:
        """
        return binascii.hexlify(bin).decode('utf-8').upper()

    def parser(self, url, wx_data=None, conversion=False):
        """
        因为c语言服务端返回数据会携带：\x00：字符，导致json解析异常
        解析vv服务器返回数据，解析为json
        :param wx_data:
        :param conversion: 是否需要二进制类型转换
        :param url:链接地址
        :return:可操作的dict
        """

        if conversion and wx_data is None:
            # 只发送token进行操作 突然发现这个地方有点反理解能力 但是改动的话要改的地方太多了 就不修改了
            data = {
                'token': self.token,
            }
        else:
            # 需要进行转换
            data = {
                'token': self.token,
                'data': self.bin2hex(wx_data)
            }

        resp = requests.post(url=url, data=json.dumps(data))
        if resp.status_code == 200:
            _json = json.loads(resp.text.strip('\x00'))
            try:
                if _json['token'] != '':
                    return _json
                else:
                    logging.error('vv服务器提示：数据错误！')
                    return None
            except ValueError:
                logging.info('提交数据出错，返回信息中没有token')
        else:
            logging.info('网络异常：请检查网络或者为vv服务器问题！')
            return None

    def creat_wx_token(self):
        """
        访问vv服务器 创建操作微信的token
        :return:
        """
        if self.new_wx:
            with open('wx.json', 'r', encoding='utf-8') as json_f:
                token = json_f.readline(1)
                self.token = json.loads(token)
                logging.info('使用本地token：二维码登录！')
                return True
        else:
            data = {
                'user': '',
                'pass': '',
                'wechat62': ''
            }
            res = requests.post(self.api + '0?1bef5220dbcfd163b6c99b52bc2742e9', data=json.dumps(data))
            if res.status_code == 200:
                _json = json.loads(res.text.strip(b'\x00'.decode()))
                if _json['message'] != 'Success':
                    logging.info('vv服务器异常或者本地网络异常获取token失败！')
                    return False
                else:
                    self.token = _json['token']
                    logging.info('token创建完成：' + _json['token'] + '且存入本地文件')
                    with open('wx.json', 'w') as json_f:
                        token = {"token": self.token}
                        json.dump(token, json_f)
                    return True

    def qr_login(self):
        """
        二维码登录
        :return:
        """
        resp = self.parser(self.api + '502?1bef5220dbcfd163b6c99b52bc2742e9', conversion=True)
        if resp is not None:
            logging.info('正在获取二维码！')
            result = requests.post(url=resp['url'], data=self.hex2bin(resp['packet'])).content
            # 访问微信，微信回传数据,在将微信回传的数据发送的vv服务器进行解析
            resp_img = self.parser(self.api + '-502?1bef5220dbcfd163b6c99b52bc2742e9', wx_data=result, conversion=True)
            if resp_img is None:
                logging.info('二维码下载失败')
            else:
                with open('qr_code.png', 'wb')as img:
                    img.write(self.hex2bin(resp_img['qrcode']))
                    logging.info('二维码保存完成！')
                    # 二维码保存完成即可开始获取扫码状态
                    self.get_qr_code()

    def get_qr_code(self):
        """
        获取扫码状态
        :return:
        """
        while 1:
            resp = self.parser(self.api + '5021?1bef5220dbcfd163b6c99b52bc2742e9', conversion=True)
            if resp is not None:
                logging.info('扫码状态包获取完成')
                res = requests.post(resp['url'], data=self.hex2bin(resp['packet'])).content
                result = self.parser(self.api + '-5021?1bef5220dbcfd163b6c99b52bc2742e9', wx_data=res)
                logging.info(result)
                if result.get(u'type') == "2":
                    print('扫码完成')
                    self.login()
                    break
                else:
                    time.sleep(1)

    def login(self):
        """
        扫码完成 密码登录等最后一步都需要获取此包完成登录
        :return:
        """
        _json = self.parser(self.api + '701?1bef5220dbcfd163b6c99b52bc2742e9',conversion=True)
        if _json is not None:
            logging.info('二次登录包获取完成')
            resp = requests.post(url=_json['url'], data=self.hex2bin(_json['packet'])).content
            result = self.parser(self.api + '-701?1bef5220dbcfd163b6c99b52bc2742e9', wx_data=resp)
            if result.get(u'type', 0) == '-301':
                return self.login()  # 重新登录
            else:
                logging.info('微信登录成功，创建tcp链接')
                self.creat_tcp(host=result.get(u'tcpip', 0))
                threading.Thread(target=self.heartbeat()).start()
                time.sleep(10)
                threading.Thread(target=self.sync_msg()).start()

    def creat_tcp(self, host):
        port = 443  # 使用443端口进行连接
        addr = (host, port)
        self.tcpClient.connect(addr)
        logging.info('创建tcp完成')
        threading.Thread(target=self.accept_tcp_msg()).start()

    def heartbeat(self):
        """
        与vv服务器的心跳维持
        当新消息产生 tcp会发通知
        :return:
        """
        while 1:
            _json = self.parser(self.api + '518?1bef5220dbcfd163b6c99b52bc2742e9',conversion=True)
            if _json is not None:
                logging.info('心跳发送成功！')
                self.tcpClient.send(self.hex2bin(_json['packet']))
            time.sleep(15)

    def accept_tcp_msg(self):
        """
        接受tcp消息
        :return:
        """
        while True:
            data = self.tcpClient.recv(1024)
            print('data:', data)
            data = [c for c in data[8:8 + 4]]
            print('收到心跳消息：{}'.format(data))
            if self.heartbeat_bytes == data:
                logging.info('获取到心跳反馈')
            elif self.info_bytes == data:
                logging.info('收到心跳可同步消息')
                self.sync_msg()
            time.sleep(15)

    def sync_msg(self):
        """
        同步信息
        :return:
        """
        _json = self.parser(self.api + '138?1bef5220dbcfd163b6c99b52bc2742e9', conversion=True)
        if _json is not None:
            logging.info('同步消息开始')
            resp = requests.post(url=_json[u'url'], data=_json[u'packet']).content
            result = self.parser(self.api + '', wx_data=resp)
            if u'msglist' in str(result):
                msg_list = result[u'msglist']
                for msg in msg_list:
                    print('收到微信消息:', msg)

    def two_login(self):
        """
        二次登录，读取本地token
        :return:
        """
        logging.info('登录方式：二次登录')
        with open('wx.json', 'r')as json_f:
            self.token = json.load(json_f)['token']
            logging.info('本地token读取完成：' + self.token)
        _json = self.parser(self.api + '702?1bef5220dbcfd163b6c99b52bc2742e9', conversion=True)
        if _json is not None:
            logging.info('二次登录包获取完成！')
            resp = requests.post(url=_json['url'],data=self.hex2bin(_json[u'packet'])).content
            result = self.parser(self.api + '-702?1bef5220dbcfd163b6c99b52bc2742e9', wx_data=resp)
            if result is not None:
                if result[u'type'] == '0':
                    self.creat_tcp(host=result.get(u'tcpip', 0))
                    threading.Thread(target=self.heartbeat()).start()
                    time.sleep(10)
                    threading.Thread(target=self.sync_msg()).start()


if __name__ == '__main__':
    wx = Wechat()
    wx.run()
