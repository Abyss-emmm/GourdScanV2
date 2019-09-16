# coding: utf-8

"""
Config and update/reload file
get test param:
config.load()["test"]
"""

import warnings
import json
import os
import out

from lib.settings import CHECK_CONF_FILE
from lib.settings import RULES_CONF_FILE
from lib.settings import RULES_PATH
from lib.settings import PLUGIN_CONF_PATH
from lib.settings import PLUGIN_PATH


warnings.filterwarnings("ignore")

class Config_file():
    def __init__(self,path):
        self.conf = None
        self.path = path
    def load(self):
        with open(self.path) as con:
            try:
                self.conf = json.load(con)
            except:
                out.error("conf.json error, please download another one and replace it.")
                exit()
    def update(self):
        with open(self.path, 'w') as con:
            content = json.dumps(self.conf).replace("{", "{\n").replace("}", "\n}").replace(", ", ",\n").replace("'", '"').replace("[","[\n").replace("]","\n]")
            con.write(content)
            return
config_file = Config_file(CHECK_CONF_FILE)
plugin_file = Config_file(PLUGIN_CONF_PATH)

def init_pluginconf():
    for root,_,files in os.walk(PLUGIN_PATH):
        dirs = _
        break
    if hasattr(plugin_file.conf,"keys") and "all" in plugin_file.conf.keys():
        plugin_file.conf['all'] = dirs
    else:
        plugin_file.conf = {"all":dirs,"use":[]}
    plugin_file.update()
    plugin_file.load()


def load():
    with open(CHECK_CONF_FILE) as con:
        try:
            conf = json.load(con)
            return conf
        except:
            out.error("conf.json error, please download another one and replace it.")
            exit()

def update(conf):
    with open(CHECK_CONF_FILE, 'w') as con:
        content = json.dumps(conf).replace("{", "{\n").replace("}", "\n}").replace(", ", ",\n").replace("'", '"')
        con.write(content)
        return


def load_rule():
    with open(RULES_CONF_FILE) as con:
        conf = json.load(con)
        return conf


def update_rule(rule):
    with open(RULES_CONF_FILE, 'w') as con:
        content = json.dumps(rule)
        con.write(content)


def rule_read(name, get_file_handle=None):
    if get_file_handle:
        return os.path.join(RULES_PATH, name + '.rule')
    with open(os.path.join(RULES_PATH, name + '.rule'),'rb') as con:
        content = con.read()
        return content


def rule_write(name, rule):
    with open(os.path.join(RULES_PATH, name + '.rule'), "wb") as con:
        con.write(rule)
