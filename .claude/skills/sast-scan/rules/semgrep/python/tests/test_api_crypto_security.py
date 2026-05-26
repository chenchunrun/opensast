import logging
import requests
import xml.dom.minidom
from string import Template
from jinja2 import Environment
from Crypto.Cipher import DES

logger = logging.getLogger(__name__)


# ruleid: python.security.template-injection
Template(user_input)

# ok: python.security.template-injection
Template("hello ${name}")

# ruleid: python.security.template-injection
Environment(loader=loader, autoescape=False)

# ok: python.security.template-injection
Environment(loader=loader, autoescape=True)

# ruleid: python.security.nosql-injection
{"$where": user_input}

# ok: python.security.nosql-injection
{"$where": "status == 'active'"}

# ruleid: python.security.xml-external-entity
xml.dom.minidom.parseString(xml_data)

# ok: python.security.xml-external-entity
defusedxml.ElementTree.parse(xml_data)

# ruleid: python.security.logging-sensitive-data
logger.debug(password)

# ok: python.security.logging-sensitive-data
logger.info("user logged in")

# ruleid: python.security.ldap-injection
ldap_conn.search_s("uid=" + username + ",ou=users", scope)

# ok: python.security.ldap-injection
ldap_conn.search_s("ou=users", scope)

# ruleid: python.security.des-usage
DES.new(key)

# ok: python.security.des-usage
AES.new(key)

# ruleid: python.security.http-only-sensitive-query
requests.get(url, params={"password": pwd})

# ok: python.security.http-only-sensitive-query
requests.post(url, json={"password": pwd})

# ruleid: python.security.exception-broad
try:
    run_task()
except:
    handle_error()

# ok: python.security.exception-broad
try:
    run_task()
except ValueError:
    handle_error()
