import json
import logging
import yaml
from urllib.parse import urlparse, parse_qsl

CONFIG_FILE = "config.yaml"


class Config:
    FILE_DICT = [""]
    TRAVERSAL_DICT = [""]
    SUFFIX_DICT = [""]
    PATH_TRAVERSAL_DICT = []

    def __init__(self):
        with open(CONFIG_FILE, 'r') as file:
            config = yaml.safe_load(file)

        self.FILE_DICT = config.get("file_dict", [""])
        self.TRAVERSAL_DICT = config.get("traversal_dict", [""])
        self.SUFFIX_DICT = config.get("suffix_dict", [""])
        multiple = [0, 1, 2, 3, 10]
        for file in self.FILE_DICT:
            for t in self.TRAVERSAL_DICT:
                for s in self.SUFFIX_DICT:
                    for i in multiple:
                        if i > 3:
                            self.PATH_TRAVERSAL_DICT.append(f"{t * i}a/{t * i}{file}{s}")
                        self.PATH_TRAVERSAL_DICT.append(f"{t * i}{file}{s}")
        logging.info(f"[*] Loaded {len(self.PATH_TRAVERSAL_DICT)} path traversal payloads from '{CONFIG_FILE}'")


def generate_payloads(request_params, path_traversal_dict):
    payloads = []
    if request_params:
        payloads.append(request_params)
        leaf_values = get_leaf_values(request_params)
        for traversal_payload in path_traversal_dict:
            for original_value in leaf_values:
                new_params = replace_leaf_value(request_params, original_value, traversal_payload)
                payloads.append(new_params)
    logging.info(f"[*] Generated {len(payloads)} payloads")
    return payloads


def gen_uri_payloads(url, dicts):
    payloads = []
    parsed_url = urlparse(url)
    uri = parsed_url.path
    if uri == "":
        uri = "/"
        for d in dicts:
            payloads.append(uri + d)
    elif uri[-1] == "/":
        for d in dicts:
            payloads.append(uri + d)
        for d in dicts:
            payloads.append(uri[:-1] + d)
    else:
        for d in dicts:
            payloads.append(uri + d)
        for d in dicts:
            payloads.append(uri + "/" + d)
        uri = "/".join(uri.split("/")[:-1]) + "/"
        for d in dicts:
            payloads.append(uri + d)

    return payloads


def get_leaf_values(data):
    leaf_values = []

    if isinstance(data, dict):
        for value in data.values():
            leaf_values.extend(get_leaf_values(value))
    elif isinstance(data, list):
        for item in data:
            leaf_values.extend(get_leaf_values(item))
    else:
        leaf_values.append(data)

    return leaf_values


def replace_leaf_value(data, original_value, new_value):
    if isinstance(data, dict):
        new_data = {}
        for key, value in data.items():
            new_data[key] = replace_leaf_value(value, original_value, new_value)
    elif isinstance(data, list):
        new_data = []
        for item in data:
            new_data.append(replace_leaf_value(item, original_value, new_value))
    else:
        if data == original_value:
            return new_value
        else:
            return data

    return new_data


def parse_request(request_data):
    try:
        request_lines = request_data.decode().split("\r\n")
        request_line = request_lines[0].split()
        method = request_line[0]
        uri = request_line[1]
        headers = {}
        body = None

        for line in request_lines[1:]:
            if line:
                header, value = line.split(":", 1)
                headers[header.strip()] = value.strip()
            else:
                body = "\r\n".join(request_lines[request_lines.index(line) + 1:]).encode()
                break

        url = "http://" + headers["Host"] + uri
        parsed_url = urlparse(url)
        logging.info(f"[*] Parsed URL: {parsed_url}")
        query_params = dict(parse_qsl(parsed_url.query))

        body_params = []
        if method.upper() == "POST":
            content_type = headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" in content_type:
                body_params = dict(parse_qsl(body.decode()))
            elif "application/json" in content_type:
                try:
                    json_data = json.loads(body.decode())
                    body_params = json_data
                except json.JSONDecodeError:
                    print("Error decoding JSON request body")

        return method, url, headers, query_params, body_params
    except Exception as e:
        print(f"Error parsing request data: {e}")
        return None
