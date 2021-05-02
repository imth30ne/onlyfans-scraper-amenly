r"""
               _          __                                                                      
  ___   _ __  | | _   _  / _|  __ _  _ __   ___         ___   ___  _ __   __ _  _ __    ___  _ __ 
 / _ \ | '_ \ | || | | || |_  / _` || '_ \ / __| _____ / __| / __|| '__| / _` || '_ \  / _ \| '__|
| (_) || | | || || |_| ||  _|| (_| || | | |\__ \|_____|\__ \| (__ | |   | (_| || |_) ||  __/| |   
 \___/ |_| |_||_| \__, ||_|   \__,_||_| |_||___/       |___/ \___||_|    \__,_|| .__/  \___||_|   
                  |___/                                                        |_|                
"""

import hashlib
import json
import pathlib
import time
from urllib.parse import urlparse

from .profiles import get_current_profile
from .prompts import auth_prompt, ask_make_auth_prompt
from ..constants import configPath, authFile


def read_auth():
    profile = get_current_profile()

    p = pathlib.Path.home() / configPath / profile
    if not p.is_dir():
        p.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            with open(p / authFile, 'r') as f:
                auth = json.load(f)
            break
        except FileNotFoundError:
            print(
                "You don't seem to have an `auth.json` file. Please fill the following out:")
            make_auth(p)
    return auth


def edit_auth():
    profile = get_current_profile()

    p = pathlib.Path.home() / configPath / profile
    if not p.is_dir():
        p.mkdir(parents=True, exist_ok=True)

    try:
        with open(p / authFile, 'r') as f:
            auth = json.load(f)
        make_auth(p, auth)

        print('Your `auth.json` file has been edited.')
    except FileNotFoundError:
        if ask_make_auth_prompt():
            make_auth(p)


def make_auth(path, auth=None):
    if not auth:
        auth = {
            'auth': {
                'app-token': '33d57ade8c02dbc5a333db99ff9ae26a',
                'sess': '',
                'auth_id': '',
                'auth_uid_': '',
                'user_agent': '',
                'x-bc': ''
            }
        }

    auth['auth'].update(auth_prompt(auth['auth']))

    with open(path / authFile, 'w') as f:
        f.write(json.dumps(auth, indent=4))


def make_headers(auth):
    headers = {
        'accept': 'application/json, text/plain, */*',
        'app-token': auth['auth']['app-token'],
        'user-id': auth['auth']['auth_id'],
        'x-bc': auth['auth']['x-bc'],
        'referer': 'https://onlyfans.com',
        'user-agent': auth['auth']['user_agent'],
    }
    return headers


def add_cookies(client):
    profile = get_current_profile()

    p = pathlib.Path.home() / configPath / profile
    with open(p / authFile, 'r') as f:
        auth = json.load(f)

    domain = 'onlyfans.com'

    client.cookies.set('sess', auth['auth']['sess'], domain=domain)
    client.cookies.set('auth_id', auth['auth']['auth_id'], domain=domain)
    if auth['auth']['auth_uid_']:
        client.cookies.set(
            f"auth_uid_{auth['auth']['auth_id']}", auth['auth']['auth_uid_'], domain=domain)


# def parse_cookies(cookies: dict) -> str:
#     two_fa = 'auth_uid_'
#     auth_uid_ = cookies[two_fa]

#     del cookies[two_fa]
#     if auth_uid_:
#         cookies[two_fa + cookies['auth_id']] = auth_uid_

#     cookie_strs = ['{}={}'.format(k, v) for k, v in cookies.items()]
#     cookie = '; '.join(cookie_strs)
#     return cookie


def create_sign(link, headers):
    """
    credit: DC and hippo guy
    """
    time2 = str(round(time.time() * 1000))

    path = urlparse(link).path
    query = urlparse(link).query
    path = path if not query else f"{path}?{query}"

    static_param = "BcsLYSyemJCNrob8u6QWziudT5Xx4LlO"

    a = [static_param, time2, path, "10319373"]
    msg = "\n".join(a)

    message = msg.encode("utf-8")
    hash_object = hashlib.sha1(message)
    sha_1_sign = hash_object.hexdigest()
    sha_1_b = sha_1_sign.encode("ascii")
    checksum = sha_1_b[15] + sha_1_b[3] + sha_1_b[27] + sha_1_b[38] + sha_1_b[31] + \
        sha_1_b[23] + sha_1_b[4] + sha_1_b[35] + sha_1_b[9] + sha_1_b[25] + \
        sha_1_b[30] + sha_1_b[22] + sha_1_b[10] + sha_1_b[26] + sha_1_b[23] + \
        sha_1_b[19] + sha_1_b[0] + sha_1_b[18] + sha_1_b[27] + sha_1_b[6] + \
        sha_1_b[2] + sha_1_b[33] + sha_1_b[18] + sha_1_b[37] + sha_1_b[0] + \
        sha_1_b[34] + sha_1_b[23] + sha_1_b[38] + sha_1_b[25] + sha_1_b[14] + \
        sha_1_b[23] + sha_1_b[6] - 100

    final_sign = "3:{}:{:x}:608c48da".format(sha_1_sign, abs(checksum))

    headers.update(
        {
            'sign': final_sign,
            'time': time2
        }
    )
    return headers
