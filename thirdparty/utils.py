#encoding:utf-8
import json
import re
import os
import pickle
import time
import requests
from lib.ordereddict import OrderedDict
from xml.dom import minidom
from urllib import unquote_plus,quote
from lib.settings import PARAM_TYPE_XML,PARAM_TYPE_JSON,PARAM_TYPE_TEXT,PAYLOAD_MODE_APPEND,PAYLOAD_MODE_REPLACE,PARAM_DATA_JSON

def paramtoDict(parameters):
    testableParameters = OrderedDict()
    splitparams = parameters.split("&")
    for element in splitparams:
        parts = element.split("=")
        if len(parts) != 2 :
            raise Exception("There is no = or more than one = find in params", element)
        parameter = parts[0]
        value = unquote_plus(parts[1]) #decode + to space
        if islikejson(value):
            try:
                jsondata = json.loads(value)
                testableParameters[parameter] = {'type':PARAM_TYPE_JSON,'value':value,PARAM_TYPE_JSON:jsondata}
            except:
                testableParameters[parameter] = {'type':PARAM_TYPE_TEXT,'value':value}
        elif islikexml(value):
            try:
                xmldata = minidom.parseString(value)
                testableParameters[parameter] = {'type':PARAM_TYPE_XML,'value':value,PARAM_TYPE_XML:xmldata}
            except:
                testableParameters[parameter] = {'type':PARAM_TYPE_TEXT,'value':value}
        else:
            testableParameters[parameter] = {'type':PARAM_TYPE_TEXT,'value':value}
    return testableParameters

def islikejson(data):
    regex = r'\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'
    match = re.search(regex,data,flags=re.S)
    if match:
        return True
    else:
        return False

def islikexml(data):
    regex = r'\A\s*<[^>]+>(.+>)?\s*\Z'
    match = re.search(regex,data,flags=re.S)
    if match:
        return True
    else:
        return False

def walk(requestdata,payload,mode,paramname,head,current = None):
    def replace(head, current, key, mode, payload):
        original  = current[key]
        if mode == PAYLOAD_MODE_REPLACE:
            current[key] = payload
            newjsondata = json.dumps(head)
            current[key] = original
            newrequestdata = re.sub(
                r'%s=.*?&' % paramname, r'%s=%s&' % (paramname, quote(newjsondata)), requestdata + '&')
            return newrequestdata[:-1]
        elif mode == PAYLOAD_MODE_APPEND:
            current[key] = "%s%s" % (original, payload)
            newjsondata = json.dumps(head)
            current[key] = original
            newrequestdata = re.sub(r'%s=.*?&' % paramname, r'%s=%s&' %
                            (paramname, quote(newjsondata)), requestdata + '&')
            return newrequestdata[:-1]
        else:
            return requestdata

    if current is None:
        current = head
    if isListLike(current):
        if isinstance(current,list):
            for key in range(0,len(current)):
                value = current[key]
                if isinstance(value, (list,tuple,set,dict)):
                    if value:
                        for p in walk(requestdata,payload,mode,paramname,head,value):
                            yield p
                elif isinstance(value,(bool,int,float,basestring)):
                    if isinstance(value,bool):
                        #send to info messagfe
                        yield replace(head,current,key,mode,payload)
                    else:
                        yield replace(head,current,key,mode,payload)
    elif isinstance(current,dict):
        for key in current.keys():
            value = current[key]
            if isinstance(value, (list,tuple,set,dict)):
                if value:
                    for p in walk(requestdata,payload,mode,paramname,head,value):
                        yield p
            elif isinstance(value,(bool,int,float,basestring)):
                if isinstance(value,bool):
                    #send to info message
                    yield replace(head,current,key,mode,payload)
                else:
                    yield replace(head,current,key,mode,payload)

def isListLike(value):
    return isinstance(value, (list, tuple, set))

def replacepayload4text(requestdata,param,data,payload,mode):
    if mode == PAYLOAD_MODE_REPLACE:
        newdata = payload
        newrequestdata = re.sub(r'%s=.*?&' % param, r'%s=%s&' % (param, quote(newdata)), requestdata + '&')
        return newrequestdata[:-1]
    elif mode == PAYLOAD_MODE_APPEND:
        newdata = data+payload
        newrequestdata = re.sub(r'%s=.*?&' % param, r'%s=%s&' % (param, quote(newdata)), requestdata + '&')
        return newrequestdata[:-1]
    else:
        return ""

def request_payload_allparams(request,payload,mode = PAYLOAD_MODE_APPEND):
    params = pickle.loads(request['params'])
    for paramfrom in params.keys():
        # replace query data,use uri directly,and can pass to time_requests's url param
        querydata = request['url']
        method = request['method']
        if method == "POST":
            postdata = request['postdata']
        for param in params[paramfrom].keys():
            paramdata = params[paramfrom][param]
            type = paramdata['type']
            if type == PARAM_TYPE_JSON:
                data = paramdata[type]
                if method == 'GET':
                    for payloaddata in walk(querydata,payload,mode,param,data):
                        res,times = time_requests(request['method'], payloaddata, request['headers'])
                        yield param,res,times
                if method == 'POST':
                    if paramfrom == "query":
                        for payloaddata in walk(querydata,payload,mode,param,data):
                            res,times = time_requests(request['method'], payloaddata, request['headers'],request['postdata'])
                            yield param,res,times
                    if paramfrom == "postdata":
                        for payloaddata in walk(postdata,payload,mode,param,data):
                            res,times = time_requests(request['method'], request['url'], request['headers'],payloaddata)
                            yield param,res,times
            if type == PARAM_TYPE_TEXT:
                data = paramdata['value']
                if method == 'GET':
                    payloaddata = replacepayload4text(querydata,param,data,payload,mode)
                    res,times = time_requests(request['method'], payloaddata, request['headers'])
                    yield param,res,times
                if method == 'POST':
                    if paramfrom == "query":
                        payloaddata = replacepayload4text(querydata,param,data,payload,mode)
                        res,times = time_requests(request['method'], payloaddata, request['headers'],request['postdata'])
                        yield param,res,times
                    if paramfrom == "postdata":
                        payloaddata = replacepayload4text(postdata,param,data,payload,mode)
                        res,times = time_requests(request['method'], request['url'], request['headers'],payloaddata)
                        yield param,res,times
            if type == PARAM_DATA_JSON:
                data = paramdata[type]
                postdata_tmp = "%s=%s" % (param,data)
                idx = len(PARAM_DATA_JSON)+1
                if method == 'POST':
                    if paramfrom == "postdata":
                        for payloaddata in walk(postdata_tmp,payload,mode,param,data):
                            payloaddata = payloaddata[idx:]
                            res,times = time_requests(request['method'], request['url'], request['headers'],payloaddata)
                            tmp = ""
                            for i in range(0,len(payloaddata)+1):
                                tmp += payloaddata[i*80:(i+1)*80]+"\n"
                            #fake the param name ,so return all payloaddata
                            yield tmp,res,times

def time_requests(method, url, headers, postdata=""):
    try:
        time0 = time.time()
        if method == 'POST':
            res = requests.post(url=url, data=postdata, headers=headers)
        else:
            res = requests.get(url=url, headers=headers)
        time1 = time.time()
        return res.content, time1-time0
    except Exception as e:
        print(e)
        return "Error", 0


def getkey(filepath):
    path = os.path.abspath(filepath)
    dir,filename = os.path.split(path)
    dir = os.path.basename(dir)
    return "/".join([dir,filename])
