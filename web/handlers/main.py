#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import base64
import urllib
import threading
import urlparse

import tornado.web

from lib.redisopt import conn,content_deal
from lib import out
from lib import scan
from lib import secure
from lib import config
from lib import session
from thirdparty.exploit import Exploitdb
from proxy import pyscapy, mix_proxy, proxy_io
from web.handlers.base import BaseHandler, authenticated

class PageNotFoundHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("404.html")


class LogoutHandler(BaseHandler):

    @authenticated
    def get(self):
        session.destroy(self.get_cookie("ysrc_token"))
        self.set_header("Location", "/")
        self.set_status(302)
        return


class LoginHandler(tornado.web.RequestHandler):

    def get(self):
        return self.render("login.html")

    def post(self):
        account = secure.clear(self.get_argument("account"))
        password = secure.clear(self.get_argument("password"))
        if account == config.config_file.conf['account'] and password == config.config_file.conf['password']:
            cookie = session.new(self.request.remote_ip)
            self.set_cookie("ysrc_token", cookie, expires_days=int(config.config_file.conf["session_expires_time"]))
            session.update(cookie)
            self.set_header("Location", "/")
            self.set_status(302)
            return
        else:
            location = "/login"
            content = "Something wrong with you account or password!"
            return self.render("302.html", location=location, content=content)


class IndexHandler(BaseHandler):

    @authenticated
    def get(self):
        waiting = conn.lrange("waiting", 0, 15)
        running = conn.lrange("running", 0, 15)
        finished = conn.lrange("finished", 0, 15)
        vulnerable = conn.lrange("vulnerable", 0, 15)
        stats_all = {}
        for i in [waiting, running, finished, vulnerable]:
            for reqhash in i:
                try:
                    decode_results = json.loads(base64.b64decode(conn.hget("results", reqhash)))
                except:
                    decode_results = {'stat':0}
                stats = ['success', 'info', 'warning', "danger"]
                stat = decode_results['stat']
                stat = stats[stat]
                stats_all[reqhash] = stat
        self.render("index.html", waiting_num=conn.llen("waiting"), running_num=conn.llen("running"), finished_num=conn.llen("finished"), vulnerable_num=conn.llen("vulnerable"), waiting=waiting, running=running, finished=finished, vulnerable=vulnerable, time=config.config_file.conf["flush_time"], stats_all=stats_all)
        return


class ConfHandler(BaseHandler):

    @authenticated
    def get(self):
        return self.render("config.html", config = config.config_file.conf)

    @authenticated
    def post(self):
        conf_all = config.config_file.conf
        for i in self.request.body.split("&"):
            para = secure.clear(urllib.unquote(i.split("=", 1)[0]))
            value = secure.clear(urllib.unquote(i.split("=", 1)[1]))
            if para in conf_all.keys():
                conf_all[para] = value
#        config.update(conf_all)
        config.config_file.update()
        return self.render("config.html", config=config.config_file.conf)

class PluginConfUpdate(BaseHandler):
    @authenticated
    def get(self):
        config.init_pluginconf()
        return self.write(out.jump("/plugin_conf"))

    @authenticated
    def post(self):
        config.init_pluginconf()
        return self.write(out.jump("/plugin_conf"))

class PluginConf(BaseHandler):
    @authenticated
    def get(self):
        plugins = {}
        use = config.plugin_file.conf["use"]
        for p in config.plugin_file.conf["all"]:
            if p in use:
                plugins[p] = {"true":"checked","false":""}
            else:
                plugins[p] = {"true":"","false":"checked"}
        return self.render("plugin_config.html",plugins=plugins)
    @authenticated
    def post(self):
        use = []
        for plugin in config.plugin_file.conf["all"]:
            on = self.get_argument(plugin+"_start")
            if on == "true":
                use.append(plugin)
        config.plugin_file.conf["use"] = use
        config.plugin_file.update()
        expdb = Exploitdb()
        expdb.init()
        return self.write(out.jump("/plugin_conf"))

class ScanConfigHandler(BaseHandler):

    @authenticated
    def get(self):
        start = {}
        rule = ["sqlireflect", "sqlitime", "sqlmap", "xpath", "xss", "lfi", "ldap", "sqlibool"]
        for i in rule:
            start[i + "_true"] = ""
            start[i + "_false"] = "checked"
        for i in config.load_rule()["scan_type"]:
            start[i + "_true"] = "checked"
            start[i + "_false"] = ""
        rules = {}
        for i in rule:
            rules[i] = config.rule_read(i)
        return self.render("scan_config.html", config=config.config_file.conf, start=start, rules=rules, scan_stat=config.config_file.conf['scan_stat'], sqlmap_api=config.load_rule()['sqlmap_api'])

    @authenticated
    def post(self):
        start = []
        rule = ["sqlireflect", "sqlitime", "sqlmap", "xpath", "xss", "lfi", "ldap", "sqlibool"]
        conf = config.load_rule()
        for i in rule:
            on = self.get_argument(i + "_start")
            if on == "true":
                start.append(i)
            rules = self.get_argument(i + "_rule")
            config.rule_write(i, rules)
            if i == "sqlmap":
                address = self.get_argument("sqlmap_api")
                conf['sqlmap_api'] = address
        conf['scan_type'] = start
        config.update_rule(conf)
        return self.write(out.jump("/scan_config"))


class ScanStatHandler(BaseHandler):

    @authenticated
    def get(self):
        stat = secure.clear(self.get_argument("stat"))
        config_all = config.config_file.conf
        config_all['scan_stat'] = stat
#        config.update(config_all)
        if stat.lower() == "true":
            thread = threading.Thread(target=scan.scan_start, args=())
            thread.setDaemon(True)
            thread.start()
        return self.write(out.jump("/scan_config"))


class ReqHandler(BaseHandler):

    @authenticated
    def get(self):
        try:
            request_hash = self.get_argument("hash")
            request = json.loads(base64.b64decode(conn.hget("request", request_hash)))
            if not conn.hget("results", request_hash):
                results = {}
                stat = "success"
            else:
                results = json.loads(base64.b64decode(conn.hget("results", request_hash)))
                stat = results['stat']
                stats = ['success', 'info', 'warning', "danger"]
                stat = stats[stat]
                if results['stat'] == 0:
                    results = {}
                else:
                    del results['stat']
                    for rule in results.keys():
                        if results[rule]['stat'] == 0:
                            del results[rule]
                        else:
                            results[rule]['stat'] = stats[results[rule]['stat']]
                            messages = []
                            for message in results[rule]['message']:
                                if message != "":
                                    messages.append(message)
                                results[rule]['message'] = messages
                #split the url in 80 chars
            url = request['url']
            request['url_encode'] = ""
            for i in range(len(url)/80+1):
                request['url_encode'] += url[i*80:i*80+80] + "\n"
            return self.render("req.html", request=request, results=results, stat=stat)
        except Exception, e:
            out.error(str(e))
            return self.write(str(e))


class ListHandler(BaseHandler):

    @authenticated
    def get(self):
        list_type = self.get_argument("type")
        try:
            start = int(self.get_argument("start"))
        except:
            start = 0
        page_num = int(config.config_file.conf['page_num'])
        length = conn.llen(list_type)
        last = start + page_num - 1
        page_now = start / page_num + 1
        end_page = -1 * ((-1 * length) / page_num)
        end_num = end_page * page_num - page_num
        if page_now - 2 >= 1:
            pages_first = page_now - 2
        else:
            pages_first = 1
        if page_now + 2 <= end_page:
            pages_last = page_now + 2
        else:
            pages_last = end_page
        pages = range(pages_first, pages_last + 1)
        content = conn.lrange(list_type, start, last)
        req_content = {}
        for reqhash in content:
            decode_content = json.loads(base64.b64decode(conn.hget("request", reqhash)))
            try:
                decode_results = json.loads(base64.b64decode(conn.hget("results", reqhash)))
            except:
                decode_results = {'stat': 0}
            req_content[reqhash] = decode_content['method'] + "|" + decode_content['url']
            #split the url in 80 chars
            req_content[reqhash] += "|"
            for i in range(len(req_content[reqhash].split("|")[1])/80+1):
                req_content[reqhash] += req_content[reqhash].split("|")[1][i*80:i*80+80] + "\n"
            stats = ['success', 'info', 'warning', "danger"]
            stat = decode_results['stat']
            stat = stats[stat]
            req_content[reqhash] += "|" + stat
        return self.render("list.html", page_now=page_now, page_num=page_num, pages=pages, content=content, list_type=list_type, length=length, req_content=req_content, end_num=end_num)


class ProxyHandler(BaseHandler):

    @authenticated
    def get(self):
        proxy_type = self.get_argument("type")
        conf = {}
        if proxy_type == "mix_proxy":
            conf['mix_addr'] = config.config_file.conf['mix_addr']
            conf['mix_port'] = config.config_file.conf['mix_port']
            stat = config.config_file.conf['mix_stat']
            try:
                start_stat = self.get_argument("stat")
                start_conf = config.config_file.conf
                start_conf['mix_stat'] = start_stat
#                config.update(start_conf)
                if start_stat.lower() == "true":
                    thread = threading.Thread(target=mix_proxy.main)
                    thread.setDaemon(True)
                    thread.start()
                else:
                    secure.kill(config.config_file.conf['mix_addr'], int(config.config_file.conf['mix_port']), "GE")
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        elif proxy_type == "scapy":
            conf['scapy_out'] = config.config_file.conf['scapy_out']
            conf['scapy_network_card'] = config.config_file.conf['scapy_network_card']
            stat = config.config_file.conf['scapy_stat']
            try:
                start_stat = secure.clear(self.get_argument("stat"))
                start_conf = config.config_file.conf
                start_conf['scapy_stat'] = start_stat
#                config.update(start_conf)
                if start_stat.lower() == "true":
                    thread = threading.Thread(target=pyscapy.main)
                    thread.setDaemon(True)
                    thread.start()
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        elif proxy_type == "tornado":
            conf['tornado_address'] = config.config_file.conf['tornado_address']
            conf['tornado_port'] = config.config_file.conf['tornado_port']
            stat = config.config_file.conf['tornado_stat']
            try:
                start_stat = secure.clear(self.get_argument("stat"))
                start_conf = config.config_file.conf
                start_conf['tornado_stat'] = start_stat
#                config.update(start_conf)
                if start_stat.lower() == "true" and config.config_file.conf['tornado_run_stat'] == 'false':
                    thread = threading.Thread(target=proxy_io.main)
                    thread.setDaemon(True)
                    thread.start()
                    start_conf = config.config_file.conf
                    start_conf['tornado_run_stat'] = 'true'
#                    config.update(start_conf)
                return self.write(out.jump("/proxy?type=" + proxy_type))
            except:
                pass
        else:
            return self.write(out.jump("/"))
        return self.render("proxy.html", proxy_type=proxy_type, conf=conf, stat=stat)

    @authenticated
    def post(self):
        proxy_type = self.get_argument("type")
        if proxy_type == "mix_proxy":
            conf = config.config_file.conf
            conf["mix_addr"] = secure.clear(self.get_argument("mix_addr"))
            conf["mix_port"] = secure.clear(self.get_argument("mix_port"))
#            config.update(conf)
            config.config_file.update()
        elif proxy_type == "scapy":
            conf = config.config_file.conf
            conf['scapy_out'] = secure.clear(self.get_argument('scapy_out'))
            conf['scapy_network_card'] = self.get_argument('scapy_network_card')
#            config.update(conf)
            config.config_file.update()
        elif proxy_type == "tornado":
            conf = config.config_file.conf
            conf['tornado_address'] = secure.clear(self.get_argument('tornado_address'))
            conf['tornado_port'] = secure.clear(self.get_argument('tornado_port'))
#            config.update(conf)
            config.config_file.update()
        return self.write(out.jump("/proxy?type=" + proxy_type))


class DelHandler(BaseHandler):

    @authenticated
    def get(self):
        del_type = self.get_argument("type")
        if del_type in ['waiting', 'finished', 'running', 'vulnerable']:
            conn.delete(del_type)
        elif del_type == "flushdb":
            conn.flushdb()
            return self.write(out.jump("/"))
        return self.write(out.jump("/list?type=" + del_type))

class ResetScanHandler(BaseHandler):

    @authenticated
    def get(self):
        if config.config_file.conf['scan_stat'].lower() == 'false':
            return self.write(out.jump("/"))
        stat = conn.rpoplpush("running", "waiting")
        while stat:
            stat = conn.rpoplpush("running", "waiting")
        return self.write(out.alert("reset success!", "/scan_stat?stat=true"))

class ApiHandler(BaseHandler):
    def post(self):
        try:
            headers = self.get_body_argument("headers")
            host = self.get_body_argument("host")
            method = self.get_body_argument("method")
            postdata = self.get_body_argument("postdata")
            uri = self.get_body_argument("uri")
            print uri
            packet = self.get_body_argument("packet")
        except tornado.web.MissingArgumentError:
            self.write("Params Error")
            self.fulsh()
        packet  =  base64.b64decode(packet)
        postdata = base64.b64decode(postdata)
        headers = json.loads(headers)
        content_deal(headers,host,method,postdata,uri,packet)
        return self.write("Success")

    def get(self):
        return self.write("You need post params</br>headers,host,method,postdata(base64),uri,packet(base64)")
