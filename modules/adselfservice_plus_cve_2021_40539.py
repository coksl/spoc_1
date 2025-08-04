import requests
from io import BytesIO
from base64 import b64decode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ADSelfServicePlusVuln:
    name = "ADSelfService Plus CVE-2021-40539"
    description = "ManageEngine ADSelfService Plus 身份验证绕过和RCE漏洞检测 (CVE-2021-40539)"
    author = "Security Researcher"
    group = "Identity Management"
    
    def check(self, target):
        """
        检测ManageEngine ADSelfService Plus是否存在CVE-2021-40539漏洞
        :param target: 目标URL (如 https://example.com:9251)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        result = ""
        check_url = target.rstrip("/") + "/./RestAPI/LogonCustomization"
        
        try:
            # 1. 检查漏洞是否存在
            test_payload = {"methodToCall": "previewMobLogo"}
            response = requests.post(
                check_url, 
                data=test_payload, 
                verify=False, 
                timeout=10
            )
            
            if '<script type="text/javascript">var d = new Date();' in response.text:
                # 2. 验证漏洞但不实际利用
                result = f"[{self.name}] 目标 {target}：存在CVE-2021-40539漏洞（高危）"
                
                # 3. 安全验证（不实际上传webshell）
                verify_url = target.rstrip("/") + "/help/admin-guide/test.jsp"
                verify_resp = requests.get(verify_url, verify=False, timeout=5)
                
                if verify_resp.status_code == 200:
                    result += "\n[!] 目标可能已被攻击，检测到test.jsp文件存在"
            else:
                result = f"[{self.name}] 目标 {target}：未发现CVE-2021-40539漏洞"
                
        except requests.exceptions.Timeout:
            result = f"[{self.name}] 目标 {target}：检测超时"
        except requests.exceptions.ConnectionError:
            result = f"[{self.name}] 目标 {target}：连接失败"
        except Exception as e:
            result = f"[{self.name}] 目标 {target}：检测异常 - {str(e)}"
        
        return result

    # 移除实际的利用代码，只保留检测功能
    # 原代码中的上传webshell和RCE执行方法已移除