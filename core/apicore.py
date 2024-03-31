import re
import time
import urllib
import requests
import logging

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080',
}

headers = {
    'Host': '127.0.0.1',
    'User-Agent': 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
}

auth_bypass_detected = False
scheme = 'http'  # default value


def print_msg(msg):
    if msg.startswith('[GET] ') or msg.startswith('[POST] '):
        print('\n')
    logging.info(msg)
    _msg = '[%s] %s' % (time.strftime('%H:%M:%S', time.localtime()), msg)
    print(_msg)


def process_doc(url, enable_proxy):
    base_url = urllib.parse.urlparse(url)
    base_url = base_url.scheme + "://" + base_url.netloc

    try:
        json_doc = requests.get(url, headers=headers, verify=False).json()

        if "basePath" in json_doc.keys():
            if 'http' not in json_doc['basePath']:
                base_url += json_doc['basePath']
            else:
                base_url = json_doc['basePath']  # eg:/santaba/rest
        elif "servers" in json_doc.keys():
            base_url = json_doc["servers"][0]['url']
        else:
            base_url = base_url.rstrip('/')

        paths = json_doc['paths']
        path_num = len(paths)
        logging.info("[+] {} has {} paths".format(url, len(paths)))

        #     遍历路径
        for path in json_doc['paths']:

            if "description" in json_doc['info'].keys():
                # v2
                summary = json_doc['info']['description']
            elif "title" in json_doc['info'].keys():
                # v1
                summary = json_doc['info']['title']
            else:
                summary = 'None'

            if "deprecated" in summary:
                continue
            for method in json_doc['paths'][path]:
                if method.upper() not in ['GET', 'POST', 'PUT']:
                    continue

                params_str = ''
                sensitive_words = ['url', 'path', 'uri']
                sensitive_params = []

                _api = json_doc['paths'][path][method]
                if _api.get('description') and "deprecated" in _api['description']:
                    continue
                if 'parameters' in _api:
                    parameters = _api['parameters']

                    for parameter in parameters:
                        para_name = parameter['name']
                        # mark sensitive parma
                        for word in sensitive_words:
                            if para_name.lower().find(word) >= 0:
                                sensitive_params.append(para_name)
                                break

                        if 'format' in parameter:
                            para_format = parameter['format']
                        elif 'schema' in parameter and 'format' in parameter['schema']:
                            if 'default' in parameter['schema'].keys():
                                para_format = parameter['schema']['default']
                            else:
                                para_format = parameter['schema']['format']
                        elif 'schema' in parameter and 'type' in parameter['schema']:
                            if 'default' in parameter['schema'].keys():
                                para_format = parameter['schema']['default']
                            else:
                                para_format = parameter['schema']['type']
                        elif 'schema' in parameter and '$ref' in parameter['schema']:
                            para_format = parameter['schema']['$ref']
                            para_format = para_format.replace('#/definitions/', '')
                            para_format = 'OBJECT_%s' % para_format
                        else:
                            para_format = parameter['type'] if 'type' in parameter else 'unkonwn'
                            if 'default' in parameter:
                                para_format = parameter['default']

                        if 'is_required' in parameter.keys():
                            is_required = '' if parameter['required'] else '*'
                        else:
                            is_required = ''

                        if 'default' in parameter:
                            params_str += '&%s=%s' % (para_name, para_format,)
                        else:
                            if para_format == 'string':
                                params_str += '&%s=%s%s%s' % (para_name, is_required, para_format, is_required)
                            else:
                                params_str += '&%s=%s' % (para_name, para_format)
                    params_str = params_str.strip('&')
                    if sensitive_params:
                        logging.info('[*] Possible vulnerable param found: %s, path is %s' % (
                            sensitive_params, base_url + path))

                scan_api(method, summary, base_url, path, params_str, enable_proxy=enable_proxy)

    except Exception as e:
        import traceback
        traceback.print_exc()
        logging.info()
        print_msg('[process_doc error][%s] %s' % (url, e))


def parseRequest(requestContent):
    content = requestContent.split('\n')
    base_url = re.findall(r'Host: (.*)', requestContent)[0]
    base_url = 'http://' + base_url
    method = content[0].split(' ')[0]
    uri = content[0].split(' ')[1].split('?')[0]
    cookies = re.findall(r'Cookie: (.*)', requestContent)
    if method == 'GET':
        query = content[0].split(' ')[1].split('?')[1]

    elif method == 'POST':
        query = content[-1]
    else:
        query = ''





def scan_api(method, summary, base_url, path, params_str, error_code=None, enable_proxy=False):
    # place holder
    _params_str = params_str.replace('*string*', 'aaaaaaaaaaaaaaa')
    _params_str = _params_str.replace('*int64*', '999')
    _params_str = _params_str.replace('*int32*', '999')
    _params_str = _params_str.replace('int64', '999')
    _params_str = _params_str.replace('int32', '999')
    _params_str = _params_str.replace('=string', '=testtttttttttttttt')
    _params_str = _params_str.replace('=integer', '=9999')

    url_formats = re.findall('{(.*?)}', path, flags=0)
    for ss in url_formats:
        path = path.replace('{' + ss + '}', 'test')

    api_url = base_url + path

    if not error_code:
        print_msg('[%s] %s %s' % (method.upper(), api_url, _params_str))
    if method.upper() == 'GET':
        if enable_proxy:
            r = requests.get(api_url + '?' + _params_str, proxies=proxies, headers=headers, verify=False)
        else:
            r = requests.get(api_url + '?' + _params_str, headers=headers, verify=False)
        if not error_code:
            print_msg('[Request] %s %s' % (method.upper(), api_url + '?' + _params_str))

    elif method.upper() == 'POST':

        try:
            if enable_proxy:
                r = requests.post(api_url, data=_params_str, proxies=proxies, headers=headers, verify=False)
            else:
                r = requests.post(api_url, data=_params_str, headers=headers, verify=False)
        #     if not error_code:
        #         print_msg('[Request] %s %s %s' % (method.upper(), api_url, _params_str))
        except Exception as e:
            print(e)
    elif method.upper() == 'PUT':
        try:
            if enable_proxy:
                r = requests.put(api_url, data=_params_str, proxies=proxies, headers=headers, verify=False)
            else:
                r = requests.put(api_url, data=_params_str, headers=headers, verify=False)
            if not error_code:
                print_msg('[Request] %s %s %s' % (method.upper(), api_url, _params_str))
        except Exception as e:
            print(e)
    else:
        logging.error("No method")

    content_type = r.headers['content-type'] if 'content-type' in r.headers else ''
    content_length = r.headers['content-length'] if 'content-length' in r.headers else ''
    if not content_length:
        content_length = len(r.content)
    if not error_code:
        print_msg('[Response] Code: %s Content-Type: %s Content-Length: %s' % (
            r.status_code, content_type, content_length))
    else:
        if r.status_code not in [401, 403, 404] or r.status_code != error_code:
            global auth_bypass_detected
            auth_bypass_detected = True
            print_msg('[VUL] *** URL Auth Bypass ***')
            if method.upper() == 'GET':
                print_msg('[Request] [%s] %s' % (method.upper(), api_url + '?' + _params_str))
            else:
                print_msg('[Request] [%s] %s \n%s' % (method.upper(), api_url, _params_str))
