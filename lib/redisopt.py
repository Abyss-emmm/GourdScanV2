# coding=utf-8

import json
import redis
import base64
import urlparse
import pickle

from hashlib import md5

from lib.settings import CHECK_CONF_FILE
from lib import config


'''
Connect redis and excute the command of redis from other class
Deal with packet insert things
'''

with open(CHECK_CONF_FILE) as conf:
    workerconf = json.load(conf)
    redisconf = {}
    redisconf['host'] = workerconf["redis_host"]
    redisconf['password'] = workerconf['redis_pass']
    redisconf['port'] = workerconf['redis_port']

conn = redis.StrictRedis(**redisconf)


def get_hash(host, uri, postdata):
    _uri = urlparse.urlparse(uri)
    request = '%s://%s%s?' % (_uri.scheme, _uri.netloc,_uri.path)
    dic = _uri.query.split('&')
    for param in dic:
        if param != "" and "=" in param:
            request += param.split('=')[0]+'=&'
    request += "|"
    for param in postdata.split('&'):
        if param != "" and "=" in param:
            request += param.split('=')[0]+'=&'
    url_hash = md5(request).hexdigest()
    return url_hash


def content_deal(headers, host, method, postdata, uri, packet):
    u = urlparse.urlparse(uri)
#    url = uri.split(u.netloc)[-1]
#    white_domain = config.load()['white_domain']
#    black_domain = config.load()['black_domain']
#    black_ext = config.load()['black_ext']
    white_domain = config.config_file.conf['white_domain']
    black_domain = config.config_file.conf['black_domain']
    black_ext = config.config_file.conf['black_ext']
    for ext in black_ext.split(','):
        if u.path.lower().endswith("."+ext):
            return
    for domain in black_domain.split(','):
        if u.netloc.lower().split(':')[0].endswith(domain):
            return
    if white_domain != "":
        for domain in white_domain.split(','):
            if not u.netloc.lower().split(':')[0].endswith(domain):
                return
    reqhash = get_hash(host, uri, postdata)
    if 'Gdscan' not in headers.keys():
        request = {
            'headers': headers,
            'host': host,
            'method': method,
            'postdata': postdata,
            'url': uri,
            'packet': packet
        }
        b64req = base64.encodestring(json.dumps(request))
        if conn.hsetnx("request", reqhash, b64req):
            conn.lpush("waiting", reqhash)
