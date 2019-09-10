# coding: utf-8

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHECK_CONF_FILE = os.path.join(ROOT, 'conf/', 'conf.json')

RULES_PATH = os.path.join(ROOT, 'conf/', 'rules/')

RULES_CONF_FILE = os.path.join(RULES_PATH, 'rule.conf')

SESSION_CONF_FILE = os.path.join(ROOT, 'conf/', 'session')

CONF_PATH = os.path.join(ROOT, 'conf/')

PLUGIN_CONF_PATH = os.path.join(ROOT,'conf','plugin.conf')

PLUGIN_PATH = os.path.join(ROOT,'plugins')

PAYLOAD_MODE_APPEND = r"append"

PAYLOAD_MODE_REPLACE = r"replace"

PARAM_TYPE_JSON = r"json"

PARAM_TYPE_XML = r"xml"

PARAM_TYPE_TEXT = r"text"

PARAM_DATA_JSON = r"IyNXSUxMX0RFTEVURV8jNDU2OTA="
