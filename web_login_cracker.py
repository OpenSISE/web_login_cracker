#!/usr/bin/env python
# -*- coding: utf-8 -*-
import optparse
import sys
import socket
import requests
import re
import time
import os

o_req = ""
# proxies = {"http": "http://127.0.0.1:5180"}
proxies = {}
error_username = ""
error_password = ""
error_code = ""
log_error = False
v_port = None


def web_login(username, password, cookie, code_url, use_https=False):
    global o_req
    global proxies
    global error_username
    global error_password
    global error_code
    global log_error
    if log_error is False:
        try:
            with open('log.temp', 'rb') as log_file:
                log_temp = log_file.read()
                if re.search(r"\{%u%\}.*\{%p%\}.*", log_temp):
                    log_temp = re.sub(r"\{%u%\}.*\{%p%\}.*", "{%%u%%}%s{%%p%%}%s" % (username, password), log_temp)
                    with open('log.temp', 'wb') as log_file:
                        log_file.write(log_temp)
                else:
                    with open('log.temp', 'ab') as log_file:
                        log_file.write("{%%u%%}%s{%%p%%}%s" % (username, password))
        except IOError, e:
            print e
            print "[!]Write the log file fails,you may not be able to use -R!"
            log_error = True
    login_req = o_req.replace("{%username%}", username)
    login_req = login_req.replace("{%password%}", password)
    if cookie is not None:
        cookie_list = [dict(cookie)]
    else:
        cookie_list = [{}]
        cookies = re.search(r'Cookie: (.*)\r\n', o_req)
        if cookies is not None:
            cookie_list[0] = str2cookie(cookies.group(1))
    if code_url is not None:
        code = getcode(code_url, cookie_list)
        login_req = login_req.replace("{%code%}", code)
    if use_https:
        url = "https://"
    else:
        url = "http://"
    searchobj = re.search(r'Host: (\S*)', login_req)
    url += searchobj.group(1)
    searchobj = re.search(r'\s(\S*)', login_req)
    url += searchobj.group(1)
    # HEADER
    login_req = re.sub(r'Cookie: .*\r\n', '', login_req)  # 去除请求头中的cookies
    header_list = re.findall(r'(\S*):\s(.*)\r\n', login_req)  # 提取请求头
    header = dict(header_list)
    if login_req[:4] == "POST":
        searchobj = re.search(r'\r\n\r\n(.*)', login_req)
        data = searchobj.group(1)
        data = data.strip()
        req = requests.post(url, headers=header, data=data, cookies=cookie_list[0], proxies=proxies)
        response = req.text
    elif login_req[:3] == "GET":
        req = requests.get(url, headers=header, cookies=cookie_list[0], proxies=proxies)
        response = req.text
    else:
        raise RuntimeError("[!]Request method not supported!")
    if re.search(error_password, response) is not None:
        return [0, "Password is incorrect"]
    if error_username != '':
        if re.search(error_username, response) is not None:
            return [1, "User does not exist"]
    if error_code != '':
        if re.search(error_code, response) is not None:
            return [2, "Verification code error"]
    return [3, response, req.content]


def str2cookie(cookies_str):
    cookies_str += "; "
    cookies = re.findall(r'([^=]*)=([^;]*); ', cookies_str)
    return dict(cookies)


def getcookie(url):
    req = requests.get(url)
    return req.cookies


def getcode(url, cookie):
    global proxies, v_port
    if cookie[0] == {}:
        cookies = None
    else:
        cookies = cookie[0]
    req = requests.get(url, cookies=cookies, proxies=proxies)
    code_date = req.content
    if req.cookies is not None:
        cookies = dict(req.cookies)
        cookie[0].update(cookies)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(code_date, ("127.0.0.1", v_port))
    try:
        code = s.recvfrom(1024)
    except:
        raise RuntimeError("[!]VerifyTool dose not run!")
    return str(code[0])


def main():
    global o_req, error_username, error_password, error_code, v_port
    parser = optparse.OptionParser(usage="%s -r <request file> -u <usernames file> -p <passwords file> "
                                         "--error_password <error_password_signatures>" % sys.argv[0])
    parser.add_option("-r", "--req_file", dest="request_file", type="string", help="specify web login request file")
    parser.add_option("-u", "--usernames_file", dest="usernames_file", type="string",
                      help="specify usernames dict file")
    parser.add_option("-p", "--passwords_file", dest="passwords_file", type="string",
                      help="specify passwords dict file")
    parser.add_option("-R", "--recovery", dest="recovery", action="store_true", default=False,
                      help="recovery progress")
    parser.add_option("-P", "--port", dest="VerifyTool_listen_port", type="int",
                      help="VerifyTool listen port")
    parser.add_option("-c", "--code_url", dest="code_url", type="string", help="specify verifycode url")
    parser.add_option("--https", dest="https", action="store_true", default=False,
                      help="use https protocol")
    parser.add_option("--cookie_url", dest="cookie_url", type="string", help="specify get cookies url")
    parser.add_option("--error_username", dest="error_username", type="string", help="username does not exist Keyword(regex)")
    parser.add_option("--error_password", dest="error_password", type="string", help="password error keyword(regex)")
    parser.add_option("--error_code", dest="error_code", type="string", help="verifycode Error Keywords(regex)")
    options, argvs = parser.parse_args()
    recovery = options.recovery
    if recovery:
        try:
            with open('log.temp', 'rt') as log_file:
                log_argv = log_file.read()
        except IOError, e:
            print e
            print "[!]Read log file failed!"
            sys.exit(-1)
        log_argv = log_argv.split('\n')
        log_re = re.search(r"\{%u%\}(.*)\{%p%\}(.*)", log_argv[-1])
        if log_re and len(log_re.groups()) == 2:
            log_re = re.search(r"\{%u%\}(.*)\{%p%\}(.*)", log_argv[-1])
            final_username = log_re.group(1)
            final_password = log_re.group(2)
        else:
            final_username, final_password = None, None
        log_argv = log_argv[:-1]
        options, argvs = parser.parse_args(log_argv)
    else:
        with open('log.temp', 'wb') as log_file:
            for arr in sys.argv[1:]:
                log_file.write(arr+'\n')
        final_username, final_password = None, None
    request_file = options.request_file
    usernames_file = options.usernames_file
    passwords_file = options.passwords_file
    v_port = options.VerifyTool_listen_port
    code_url = options.code_url
    cookie_url = options.cookie_url
    https = options.https
    if request_file is None or usernames_file is None or passwords_file is None or options.error_password is None:
        print parser.usage
        sys.exit(0)
    error_password = options.error_password.decode('gb2312')
    if options.error_username is not None:
        error_username = options.error_username.decode('gb2312')
    if options.error_code is not None:
        error_code = options.error_code.decode('gb2312')
        print error_code
    if code_url is not None and error_code is None:
        print "[!]Wrong Verifycode keyword is must!"
        sys.exit(0)
    if code_url is not None and v_port is None:
        print "[!]VerifyTool listen port is must!"
        sys.exit(0)
    try:
        req_file = open(request_file, 'rb')
        o_req = req_file.read()
        if  "{%%username%%}" not in o_req:
            print "[!]Can't find the username parameter in the request file"
        if not "{%%password%%}" not in o_req:
            print "[!]Can't find the password parameter in the request file"
    except IOError, e:
        print e
        raise IOError("[!]Read requests file failed!")
    try:
        u_file = open(usernames_file, 'rb')
    except IOError, e:
        print e
        raise IOError("[!]Read username dict file failed!")
    try:
        pw_file = open(passwords_file, 'rb')
    except IOError, e:
        print e
        raise IOError("[!]Read password dict file failed!")
    socket.setdefaulttimeout(5)
    usernames = u_file.readlines()
    username = [u.strip() for u in usernames]
    passwords = pw_file.readlines()
    password = [p.strip() for p in passwords]
    c1 = False
    c2 = False
    ct1 = True
    ct2 = True
    success = False
    success_result = []
    for user in username:
        if (final_username is not None and user != final_username and c1 is False):
            continue
        else:
            c1 = True
        for pwd in password:
            if (final_password is not None and pwd != final_password and c2 is False):
                continue
            else:
                c2 = True
            print "[+]Test username:%s password:%s" % (user, pwd)
            if cookie_url is not None:
                cookie = getcookie(cookie_url)
            else:
                cookie = None
            status = web_login(user, pwd, cookie, code_url, https)
            if status[0] == 2:
                for i in range(5):
                    print "[!]Wrong verification code!retry again.(%d/5)" % (i+1)
                    status = web_login(user, pwd, cookie, code_url, https)
                    if status[0] != 2:
                        break
                    elif status[0] == 2 and i == 4:
                        raise RuntimeError("[!]Verification code tool recognition error occurred！")
            if status[0] == 0:
                print "[-]Fail:%s" % status[1]
            elif status[0] == 1:
                print "[-]Fail:%s" % status[1]
                break
            else:
                success = True
                success_result.append([user, pwd])
                print "[+]Success?:\n%s" % status[1]
                try:
                    with open('success.txt', 'wb') as success_file:
                        success_file.write(status[2])
                        print "[+]Write success file %s done!" % (os.getcwd() + "\success.txt")
                        while True:
                            continue_test = raw_input("[?]Do you want to continue to test other users?(Y/N):")
                            if continue_test == 'Y' or continue_test == 'y':
                                ct1 = False
                                break
                            elif continue_test == 'N' or continue_test == 'n':
                                ct1 = False
                                ct2 = False
                                break
                except IOError, e:
                    print e
                    print "[!]Write success file fail!"
                    exit(-1)
            if ct1 is False:
                ct1 = True
                break
        if ct2 is False:
            break
        time.sleep(1.5)
    if c1 & c2 is False:
        print "[!]Recovery progress fail!"
        exit(-1)
    if success:
        print "[+]Success!"
        i = 1
        for result in success_result:
            print "[%i]Username:%sPassword:%s" % (i, result[0], result[1])
            i += 1
    else:
        print "[-]Can't find a user and password!"

if __name__ == '__main__':
    main()
