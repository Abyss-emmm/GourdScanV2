#encoding:utf-8
import os
def getpayload():
    conf = "xss.yml"
    dirname = os.path.dirname(__filename__)
    path = os.path.join(dirname,conf)
    with open(path,"r") as f:
        data = f.read()
    p = yaml.load(data,Loader=yaml.FullLoader)
    return p

def exp(request):
    payloads = getpayload()['payloads']
    message = {"request_stat": 0, "message": ""}
    normal = payloads['normal']
    returndata = {}
    for key,value in normal.items():
        for param,res,times in request_payload_allparams(request,value):
            if value.strip() in res:
                returndata[param] = returndata[param] if param in returndata.keys() else []
                returndata[param].append(key)
    if len(returndata) > 0:
        message["request_stat"] = 1
        for param in returndata.keys():
            message["message"] += "param: %s|#|payload: %s|,|" % (param,",".join(returndata[param]))
    if message["request_stat"] > 0:
        for payload in payloads['evil']:
            for param,res,times in request_payload_allparams(request,payload):
                if payload.strip() in res:
                    message["request_stat"] = 2
                    message["message"] += "payload: %s|#|param: %s|#|findstr: %s|,|" % (payload,param,payload)
    return utils.getkey(__filename__),message
