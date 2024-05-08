# TraversalHunter
Scanner for PathTraversal Vul.


## 示例漏洞
| CVE编号          | 漏洞名称                                    | 厂商         |
| ---------------- | ------------------------------------------- | ------------ |
| CVE-2010-2861    | Adobe ColdFusion 文件读取漏洞               | Adobe        |
| CVE-2015-3337    | ElasticSearch 目录穿越漏洞                  | Elastic      |
| CVE-2017-14849   | Node.js 目录穿越漏洞                        | Node.js      |
| CVE-2017-1000028 | GlassFish 任意文件读取漏洞                  | Oracle       |
| CVE-2018-7490    | uWSGI PHP目录穿越漏洞                       | uWSGI        |
| CVE-2019-3396    | Atlassian Confluence 路径穿越与命令执行漏洞 | Atlassian    |
| CVE-2021-41773   | Apache HTTP Server 2.4.49 路径穿越漏洞      | Apache       |
| CVE-2021-42013   | Apache HTTP Server 2.4.50 路径穿越漏洞      | Apache       |
| CVE-2021-43798   | Grafana 8.x 插件模块目录穿越漏洞            | Grafana Labs |
| CVE-2023-32315   | Openfire管理后台认证绕过漏洞                | Openfire     |

## 对比数据

| 漏洞             | TraversalHunter | AWVS | xpoc | vscan |
| ---------------- | --------------- | ---- | ---- | ----- |
| CVE-2010-2861    | ✅               | ✅    | ❌    | ❌     |
| CVE-2015-3337    | ✅               | ❌    | ✅    | ❌     |
| CVE-2017-14849   | ✅               | ✅    | ❌    | ❌     |
| CVE-2017-1000028 | ✅               | ✅    | ❌    | ✅     |
| CVE-2018-7490    | ✅               | ✅    | ❌    | ❌     |
| CVE-2019-3396    | ✅               | ✅    | ✅    | ✅     |
| CVE-2021-41773   | ✅               | ✅    | ✅    | ❌     |
| CVE-2021-42013   | ✅               | ✅    | ❌    | ❌     |
| CVE-2021-43798   | ✅               | ✅    | ✅    | ❌     |
| CVE-2023-32315   | ✅               | ❌    | ✅    | ❌     |
| Nginx-conf       | ✅               | ❌    | ❌    | ❌     |



