# coding=utf-8
# *****************************************************
# struts-Recon: Apache Struts CVE-2018-11776 Recon Tool
# Author:
# DevCoinfet
# Date:8/30/2018 
# find my other code at :
# Censys Dork: [8080.http.get.title:Struts2 Showcase]
# https://github.com/devcoinfet
# Tested on: [All os]
# CVE : [CVE-2018-11776]
# *****************************************************
 
from urlparse import urlparse
from threading import Thread
import httplib, sys
from Queue import Queue
import requests
import types
port = 8080
concurrent = 200
target_list = []
fingerprint_list = ['actionchaining/actionChain1!input.action','demo/struts2-showcase/index.action','2.3.15.1-showcase/showcase.action','struts2/index.action']
struts_detected_sure = []
struts_fingerprint_1 = """<a href="http://struts.apache.org/2.x/">
				<img src="/img/struts-power.gif"
				     alt="Powered by Struts"/>"""




def FingerPrintStruts(ourl):
    try:
       r = requests.get(ourl, allow_redirects=False, timeout=3)
       print(r.status_code,ourl) 
       if "200" in str(r.status_code):
           if struts_fingerprint_1  in r.content:
              local_copy = {'Url':ourl,"Struts Detected":"True"}
              struts_detected_sure.append(local_copy)
              print "Detected Struts"
    except:
        pass
 

def doWork():
    while True:
        url = q.get()
        status, url = getStatus(url)
        doSomethingWithResult(status, url)
        q.task_done()


def getStatus(ourl):
    try:
        url = urlparse(ourl)
        conn = httplib.HTTPConnection(url.netloc, timeout=3)   
        conn.request("HEAD", url.path)
        res = conn.getresponse()
        print res.headers
        return res.status, ourl
    except:
        return "error", ourl

def doSomethingWithResult(status, url):
   if type(status) is types.IntType:
      print str(type(status)) +":"+str(status), url + "\n"
      if "200"   in str(status):
         try:
            FingerPrintStruts(url)
         except:
             pass
      
for ip in open("urllist.txt"):       
    for url_appender in fingerprint_list:
        url = 'http://' + ip.rstrip()+":"+ str(port) + "/" + url_appender
        target_list.append(url)


q = Queue(concurrent * 2)
for i in range(concurrent):
    t = Thread(target=doWork)
    t.daemon = True
    t.start()
try:
    for url in target_list:
        q.put(url)
    q.join()
except KeyboardInterrupt:
    sys.exit(1)


for urls in struts_detected_sure:
    print(urls)

