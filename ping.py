# -*- coding: UTF-8 -*-

import time
import struct
import socket
import select
import sys
import os
import numpy
import tkinter
import tkinter.messagebox
import tkinter.filedialog
import json
import _thread
def chesksum(data):
    """
    校验
    """
    n = len(data)
    m = n % 2
    sum = 0
    for i in range(0, n - m, 2):
        sum += (data[i]) + ((data[i + 1]) << 8)  # 传入data以每两个字节（十六进制）通过ord转十进制，第一字节在低位，第二个字节在高位
    if m:
        sum += (data[-1])
    # 将高于16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)  # 如果还有高于16位，将继续与低16位相加
    answer = ~sum & 0xffff
    # 主机字节序转网络字节序列（参考小端序转大端序）
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

    '''
    连接套接字,并将数据发送到套接字
    '''


def raw_socket(dst_addr, imcp_packet):
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    send_request_ping_time = time.time()
    # send data to the socket
    rawsocket.sendto(imcp_packet, (dst_addr, 80))
    return send_request_ping_time, rawsocket, dst_addr

    '''
    request ping
    '''


def request_ping(data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body):
    # 把字节打包成二进制数据
    imcp_packet = struct.pack('>BBHHH32s', data_type, data_code, data_checksum, data_ID, data_Sequence, payload_body)
    icmp_chesksum = chesksum(imcp_packet)  # 获取校验和
    imcp_packet = struct.pack('>BBHHH32s', data_type, data_code, icmp_chesksum, data_ID, data_Sequence, payload_body)
    return imcp_packet
    '''
    reply ping
    '''


def reply_ping(send_request_ping_time, rawsocket, data_Sequence, timeout=2):
    while True:
        started_select = time.time()
        what_ready = select.select([rawsocket], [], [], timeout)
        wait_for_time = (time.time() - started_select)
        if what_ready[0] == []:  # Timeout
            return -1
        time_received = time.time()
        received_packet, addr = rawsocket.recvfrom(1024)
        icmpHeader = received_packet[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack(
            ">BBHHH", icmpHeader
        )
        if type == 0 and sequence == data_Sequence:
            return time_received - send_request_ping_time
        timeout = timeout - wait_for_time
        if timeout <= 0:
            return -1

    '''
    实现 ping 主机/ip
    '''


def ping(host,self):
    self.write_log_to_Text("正在检测 IP 为 "+host+" 的延时...")
    data_type = 8  # ICMP Echo Request
    data_code = 0  # must be zero
    data_checksum = 0  # "...with value 0 substituted for this field..."
    data_ID = 0  # Identifier
    data_Sequence = 1  # Sequence number
    payload_body = b'abcdefghijklmnopqrstuvwabcdefghi'  # data
    dst_addr = socket.gethostbyname(host)  # 将主机名转ipv4地址格式，返回以ipv4地址格式的字符串，如果主机名称是ipv4地址，则它将保持不变
    # print("正在 Ping {0} [{1}] 具有 32 字节的数据:".format(host, dst_addr))
    l = []
    for i in range(0, 3):
        icmp_packet = request_ping(data_type, data_code, data_checksum, data_ID, data_Sequence + i, payload_body)
        send_request_ping_time, rawsocket, addr = raw_socket(dst_addr, icmp_packet)
        times = reply_ping(send_request_ping_time, rawsocket, data_Sequence + i)
        if times > 0:
            l.append(int(times * 1000))
            time.sleep(0.7)
        else:
            self.write_log_to_Text("IP 为 "+host+" 检测失败")
    if len(l) == 0:
        return False
    l.sort()
    self.write_log_to_Text("IP 为 "+host+" 检测完成")
    return l

LOG_LINE_NUM = 0
def ping_xc(self):
    self.write_log_to_Text("开始检测")
    ping_list = []
    for a1 in self.ip.get('auth',{}):
        print(a1)
        ping_status = ping(a1,self)
        if ping_status:
            ping_list.append({'url':a1,'ms':round(numpy.mean(ping_status),2)})
        else:
            self.write_log_to_Text("检测 IP 为 "+a1+"失败")
    ping_list = sorted(ping_list, key = lambda i: i['ms'])
    print(ping_list)
    for a1 in ping_list:
        print(a1['url'],a1['ms'])
        self.init_data_Text.insert(tkinter.END, ' IP: '+a1['url'] + '\n'+' 延迟(ms): ' + str(a1['ms']) + '\n'+'\n')
    print("d")
    ping_lists = []
    for s1 in self.ip.get('session',{}):
        ping_status = ping(s1,self)
        if ping_status:
            ping_lists.append({'url':s1,'ms':round(numpy.mean(ping_status),2)})
        else:
            self.write_log_to_Text("Ping "+s1+"失败")
    ping_lists = sorted(ping_lists, key = lambda i: i['ms'])
    print(ping_list)
    for s1 in ping_lists:
        print(s1['url'],s1['ms'])
        self.result_data_Text.insert(tkinter.END, ' IP: '+s1['url'] + '\n'+' 延迟(ms): ' + str(s1['ms']) + '\n'+'\n')
    tkinter.messagebox.showinfo("检测已完成",'所有 IP 已检测完成!\n最优验证服务器 (Auth Server) IP: ' + ping_list[0]['url'] + ' 延迟(ms): ' + str(ping_list[0]['ms'])+'\n最优会话服务器 (Session Server) IP:' + ping_lists[0]['url'] + ' 延迟(ms): ' + str(ping_lists[0]['ms']))
    tkinter.messagebox.showinfo("添加 HOSTS",'请打开 C:\Windows\System32\drivers\etc 目录下的 hosts 文件\n将如下内容在 hosts 文件最后两行添加：\n'+ ping_list[0]['url'] + ' authserver.mojang.com\n' + ping_lists[0]['url'] + ' sessionserver.mojang.com\n'+'\n请务必保存!!!')
    self.start_button.configure(state='normal')

class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name


    #设置窗口
    def set_init_window(self):
        self.init_window_name.title("Mojang 服务器最优 IP 检测")           #窗口名
        #self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1068x681+10+10')
        #self.init_window_name["bg"] = "pink"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        self.init_window_name.attributes("-alpha",1.0)                          #虚化，值越小虚化程度越高
        #标签
        self.init_data_label = tkinter.Label(self.init_window_name, text="验证服务器 (Auth Server)")
        self.init_data_label.grid(row=0, column=0)
        self.result_data_label = tkinter.Label(self.init_window_name, text="会话服务器 (Session Server)")
        self.result_data_label.grid(row=0, column=12)
        self.log_label = tkinter.Label(self.init_window_name, text="日志 (Logs)")
        self.log_label.grid(row=12, column=0)
        #文本框
        self.init_data_Text = tkinter.Text(self.init_window_name, width=67, height=35)  #原始数据录入框
        self.init_data_Text.grid(row=1, column=0, rowspan=10, columnspan=10)
        self.result_data_Text = tkinter.Text(self.init_window_name, width=70, height=49)  #处理结果展示
        self.result_data_Text.grid(row=1, column=12, rowspan=15, columnspan=10)
        self.log_data_Text = tkinter.Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_data_Text.grid(row=13, column=0, columnspan=10)
        #按钮
        self.start_button = tkinter.Button(self.init_window_name, text="开 始(Start)", bg="lightblue", width=10,command=self.start_ping)  # 调用内部方法  加()为直接调用
        self.start_button.grid(row=1, column=11)
        if len(sys.argv) < 2:
            file = tkinter.filedialog.askopenfilename(title='选择配置文件 (*.json)', filetypes=[('JSON', '*.json'), ('All Files', '*')],initialdir=os.path.dirname(os.path.abspath(__file__)))
            if file == '':
                tkinter.messagebox.showinfo("提示",'已取消')
                sys.exit()
        elif os.path.exists(sys.argv[1]) and not os.path.isfile(sys.argv[1]):
            tkinter.messagebox.showinfo("提示：",'打开的文件不能为文件夹或文件不存在')
            sys.exit()
        else:
            file = sys.argv[1]
        with open(file,'r') as f:
            self.ip = json.loads(f.read())
            print(self.ip)


    #功能函数
    def start_ping(self):
        try:
            _thread.start_new_thread(ping_xc,(self,))
            self.start_button.configure(state='disable')
        except:
            self.result_data_Text.delete(1.0,tkinter.END)
            self.result_data_Text.insert(1.0,"Ping 失败")


    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('[%H:%M:%S]',time.localtime(time.time()))
        return current_time


    #日志动态打印
    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(tkinter.END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0,2.0)
            self.log_data_Text.insert(tkinter.END, logmsg_in)

def gui_start():
    init_window = tkinter.Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示

if __name__ == "__main__":
    gui_start()