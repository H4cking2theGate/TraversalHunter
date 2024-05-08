import codecs
import concurrent.futures

from urllib.parse import urlparse, quote
from core.apicore import process_doc
from util.req_utils import generate_payloads, parse_request, Config, gen_uri_payloads
import logging
import requests

requests.packages.urllib3.disable_warnings()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}


def urldecode_patch():
    import urllib3
    import requests
    from requests.utils import unquote_unreserved, InvalidURL
    def uuuu(url, allowed_chars, encoding="utf-8"):
        return url

    def uuuuu(url):
        return url

    def rrrr(uri):
        safe_with_percent = "!#$%&'()*+,/:;=?@[]~"
        safe_without_percent = "!#$&'()*+,/:;=?@[]~%"
        try:
            return quote(unquote_unreserved(uri), safe=safe_with_percent)
        except InvalidURL:
            return quote(uri, safe=safe_without_percent)

    def patched_requote_uri(uri):
        return rrrr(uri)

    requests.utils.UNRESERVED_SET = ''
    requests.utils.requote_uri = patched_requote_uri
    urllib3.util.url._encode_invalid_chars = uuuu
    urllib3.util.url._remove_path_dot_segments = uuuuu


urldecode_patch()


class TrickUrlSession(requests.Session):
    def setUrl(self, url):
        self._trickUrl = url

    def send(self, request, **kwargs):
        if self._trickUrl:
            request.url = self._trickUrl
        return requests.Session.send(self, request, **kwargs)


'''使用方法'''
s = TrickUrlSession()
s = requests.session()


def scan_url_worker(args):
    url, payload, headers, enable_proxy = args
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}{parsed_url[2]}"
    try:
        response = s.get(base_url, params=payload, headers=headers,
                         proxies=proxies if enable_proxy else None,
                         timeout=5)
        logging.info(f"[+] {response.status_code} - Get with query {payload}...")
        if check_vul(response):
            return (base_url, response.status_code)
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error scanning {payload}: {e}")
        logging.error(f"[!] Error scanning {payload}: {e}")
        return None


def scan_url(url, payloads, headers=None, enable_proxy=False, max_workers=10):
    results = []
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}{parsed_url[2]}"
    logging.info(f"[+] Scanning {base_url}")
    if enable_proxy:
        logging.info(f"[+] Using proxy: {proxies}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = []
        for payload in payloads:
            args = (url, payload, headers, enable_proxy)
            tasks.append(executor.submit(scan_url_worker, args))

        for future in concurrent.futures.as_completed(tasks):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
                    logging.info(f"[VUL] *** Path Traversal *** with query {result[1]}")
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"[!] Error: {e}")

    return results


def scan_request_worker(args):
    url, headers, query_payload, body_payload, enable_proxy, is_json = args
    results = []
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}{parsed_url[2]}"
    try:
        response = s.post(base_url, params=query_payload,
                          data=body_payload if not is_json else None,
                          json=body_payload if is_json else None,
                          headers=headers,
                          proxies=proxies if enable_proxy else None,
                          verify=False,
                          timeout=4)
        logging.info(f"[+] {response.status_code} - with query {query_payload} and {body_payload}...")
        if check_vul(response):
            results.append((base_url, f"query {query_payload} and {body_payload}", response.status_code))
            logging.info(f"[VUL] *** Path Traversal *** with query {query_payload} and {body_payload}")
    except requests.exceptions.RequestException as e:
        print(f"Error scanning {query_payload} and {body_payload}: {e}")
        logging.error(f"[!] Error scanning {query_payload} and {body_payload}: {e}")
    return results


def scan_request(url, headers, query_payloads, body_payloads, enable_proxy=False, is_json=False, max_workers=10):
    results = []
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}{parsed_url[2]}"
    logging.info(f"[+] Scanning {base_url}")
    if enable_proxy:
        logging.info(f"[+] Using proxy: {proxies}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = []
        for query_payload in query_payloads:
            args = (url, headers, query_payload, body_payloads[0] if body_payloads else None, enable_proxy, is_json)
            tasks.append(executor.submit(scan_request_worker, args))

        for body_payload in body_payloads:
            args = (url, headers, query_payloads[0] if query_payloads else None, body_payload, enable_proxy, is_json)
            tasks.append(executor.submit(scan_request_worker, args))

        for future in concurrent.futures.as_completed(tasks):
            try:
                results.extend(future.result())
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"[!] Error: {e}")

    return results


def scan_uri_worker(args):
    method, url, payload, query_params, body_params, headers, enable_proxy = args
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}"
    try:
        response = s.request(method, base_url + payload, params=query_params, data=body_params, headers=headers,
                             proxies=proxies if enable_proxy else None,
                             verify=False,
                             timeout=4)
        logging.info(f"[+] {response.status_code} - {method} with uri {payload}...")
        if check_vul(response):
            return (base_url, payload, response.status_code)
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error scanning {payload}: {e}")
        logging.error(f"[!] Error scanning {payload}: {e}")
        return None


def scan_uri(method, url, payloads, query_params, body_params, headers, enable_proxy=False, max_workers=10):
    results = []
    parsed_url = list(urlparse(url))
    base_url = f"{parsed_url[0]}://{parsed_url[1]}"
    logging.info(f"[+] Scanning {base_url} with uri payloads...")
    if enable_proxy:
        logging.info(f"[+] Using proxy: {proxies}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = []
        for payload in payloads:
            args = (method, url, payload, query_params, body_params, headers, enable_proxy)
            tasks.append(executor.submit(scan_uri_worker, args))

        for future in concurrent.futures.as_completed(tasks):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
                    logging.info(f"[VUL] *** Path Traversal *** with query {result[1]}")
            except Exception as e:
                print(f"Error: {e}")
                logging.error(f"[!] Error: {e}")

    return results


def scan(request, enable_proxy=False):
    results = []
    config = Config()
    if isinstance(request, str):
        # 如果是URL字符串,直接进行GET请求扫描
        text = requests.get(request).text
        if text.strip().startswith('{"swagger":"'):
            logging.info(f"[+] Found swagger doc type")
            with codecs.open('api-docs.json', 'w', encoding='utf-8') as f:
                f.write(text)
            process_doc(request, enable_proxy=enable_proxy)
        else:
            logging.info(f"[+] Found url type request")
            url = request
            payloads = generate_payloads(url, config.PATH_TRAVERSAL_DICT)
            results = scan_url(url, payloads)
    else:
        # 如果是HTTP请求数据,解析请求并发送对应的请求
        logging.info(f"[+] Found HTTP request file type")
        parsed_request = parse_request(request)
        if parsed_request is None:
            return []
        method, url, headers, query_params, body_params = parsed_request
        uri_payloads = gen_uri_payloads(url, config.PATH_TRAVERSAL_DICT)
        query_payloads = generate_payloads(query_params, config.PATH_TRAVERSAL_DICT)
        body_payloads = generate_payloads(body_params, config.PATH_TRAVERSAL_DICT)

        if uri_payloads:
            results.extend(
                scan_uri(method, url, uri_payloads, query_params, body_params, headers, enable_proxy=enable_proxy))
        if method.upper() == "GET":
            results.extend(scan_url(url, query_payloads, headers=headers, enable_proxy=enable_proxy))
        else:
            if "x-www-form-urlencoded" in headers["Content-Type"]:
                results.extend(scan_request(url, headers, query_payloads, body_payloads, enable_proxy=enable_proxy))
            elif "json" in headers["Content-Type"]:
                results.extend(scan_request(url, headers, query_payloads, body_payloads, enable_proxy=enable_proxy,
                                            is_json=True))

    return results


def check_vul(response):
    vul_str = [
        "root:x:0:0:",
        "<web-app xmlns=\"http://xmlns.jcp.org/xml/ns/javaee\"",
        "for 16-bit app",
        "java.lang.NullPointerException"
    ]
    for v in vul_str:
        if v in response.text:
            return True
    return False
