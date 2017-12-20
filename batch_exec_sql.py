#!/usr/bin/env python
#-*- coding:utf-8 -*-

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import pymysql
import argparse
import sys
import os
import time

reload(sys)
sys.setdefaultencoding('utf8')


"""
加密 salt
"""
SALT = 'W0atk639mwiMtOuoxql31AgCvRwPUX53'

"""
账号加密相关
"""
class prpcrypt():
    def __init__(self,key):
        self.key = key
        self.mode = AES.MODE_CBC
     
    #加密函数，如果text不足16位就用空格补足为16位，
    #如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self,text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        #这里密钥key 长度必须为16（AES-128）,
        #24（AES-192）,或者32 （AES-256）Bytes 长度
        #目前AES-128 足够目前使用
        length = 32
        count = len(text)
        if count < length:
            add = (length-count)
            #\0 backspace
            text = text + ('\0' * add)
        elif count > length:
            add = (length-(count % length))
            text = text + ('\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        #所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)
     
    #解密后，去掉补足的空格用strip() 去掉
    def decrypt(self,text):
        cryptor = AES.new(self.key,self.mode,b'0000000000000000')
        plain_text  = cryptor.decrypt(a2b_hex(text))
        return plain_text.rstrip('\0')

class Account(object):
    
    @classmethod
    def ken_passwd(self):
        """获得 ken 密码"""
        pc = prpcrypt(SALT)
        e = '328c849fa7627c098f8f43f547f59bf1266e24a5caa2bfc8b4430ad47a1fa901'
        d = pc.decrypt(e) #解密
        return d

    @classmethod
    def us_monitor_passwd(self):
        """获得 ken 密码"""
        pc = prpcrypt(SALT)
        e = '82235e6033cfd23abe337438733d1a8aea802b2bd4ee11febf0a141783345f01'
        d = pc.decrypt(e) #解密
        return d


"""
MySQL查询工具
"""
class MySQLTool(object):
    """对MySQL操作的一些命令"""

    def __init__(self, host, port, user, passwd, db='', charset='utf8'):
        self.conf = {
            'host': host,
            'port': int(port),
            'user': user,
            'passwd': passwd,
            'db': db,
            'charset': charset,
        }
        self.conn = None

    def close(self):
        if self.conn: self.conn.close()

    def conn_server(self, is_dict=False):
        """链接数据库"""
        if is_dict:
            self.conf['cursorclass'] = pymysql.cursors.DictCursor

        is_alive = False

        try:
            self.conn = pymysql.connect(**self.conf)
            is_alive = True
        except:
            is_alive = False

        return is_alive

    def fetchall(self, sql):
        """获取所有的数据"""
        rs = None
        try:
            cursor = self.conn.cursor()
            cnt = cursor.execute(sql)
            rs = cursor.fetchall()
        except:
            pass
         
        return rs


    def fetchone(self, sql, is_dict=False):
        """获取所有的数据"""
        rs = None
        try:
            cursor = self.conn.cursor()
            cnt = cursor.execute(sql)
            rs = cursor.fetchone()
        except:
            pass
         
        if is_dict and rs:
            cols = [col[0] for col in cursor.description]
            rs = dict(zip(cols, rs))

        return rs

class BatchExecSQL(object):
    """批量执行sql"""

    def __init__(self):
        self.host_ports = []

    def set_host_ports(self, host_ports=[]):
        """设置host_ports"""
        for host_port in host_ports:
            host, port = host_port.strip().split(':')
            self.host_ports.append({'host':host, 'port':port})

    def set_host_ports_by_file(self, file_name=None):
        """通过文件设置host_ports"""
        with open(file_name, 'r') as f:
            self.set_host_ports(host_ports=(line.strip() for line in f if line.strip()))

    def execute(self, host, port, user, passwd, sql):
        """执行sql"""
        mt = None
        rs = None
        try:
            mt = MySQLTool(host = host,
                           port = port,
                           user = user,
                           passwd = passwd)
            mt.conn_server()
            rs = mt.fetchall(sql)
        except Exception as e:
            raise
        finally:
            mt.close()

        return rs

    def batch_execute(self, sql):
        """批量执行sql"""
        user = 'HH'
        passwd = 'oracle'
        for host_port in self.host_ports:
            host = host_port['host']
            port = host_port['port']

            rs = self.execute(host, port, user, passwd, sql)

            for item in rs: print item
        

def parse_args():
    """解析命令行传入参数"""
    usage = """
Usage Example: 
python batch_exec_sql.py --host-port="127.0.0.1:3306" --sql="show slave status"
python batch_exec_sql.py --host-port="127.0.0.1:3306" --host-port="127.0.0.1:3306" --sql="show slave status"
python batch_exec_sql.py --host-file="ip.txt" --sql="show master status"

Description:
    Check the DRC mode, table need fields
    """

    # 创建解析对象并传入描述
    parser = argparse.ArgumentParser(description = usage, 
                            formatter_class = argparse.RawTextHelpFormatter)

    # 添加 Project Name 参数
    parser.add_argument('--host-port', dest='host_ports', required=False,
                      action='append', default=None, metavar='[host:port]',
                      help='--host-ports can use multiple times')
    # 添加 MySQL Host 参数
    parser.add_argument('--host-file', dest='host_file', required = False,
                      action='store', default=None,
                      help='host:port in file and every line', metavar='host')
    # 添加 table 参数
    parser.add_argument('--sql', dest='sql', required=True,
                      action='store', type=str,
                      help='sql', metavar='sql')

    args = parser.parse_args()

    return args

def main():
    args = parse_args() # 解析传入参数

    host_ports = args.host_ports
    host_file = args.host_file
    sql = args.sql

    # 记录参数日志
    print ('param: [host_ports={host_ports}] [host_file={host_file}] [sql={sql}]'.format(
                    host_ports=host_ports, host_file=host_file, sql=sql))

    batch_exec_sql = BatchExecSQL()
 
    if host_file:
        batch_exec_sql.set_host_ports_by_file(file_name=host_file)
    elif host_ports:
        batch_exec_sql.set_host_ports(host_ports=host_ports)
    else:
        print '[Error] --host-port/--host-ports not directory'

    batch_exec_sql.batch_execute(sql=sql)

if __name__ == '__main__':
    main()
