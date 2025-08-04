import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ApacheDruidVuln:
    name = "Apache Druid RCE漏洞 (CVE-2021-25646)"
    description = "Apache Druid 远程代码执行漏洞检测"
    author = "Security Researcher"
    group = "Big Data"
    
    def check(self, target):
        """
        检测Apache Druid是否存在CVE-2021-25646漏洞
        :param target: 目标URL (如 http://example.com:8081)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        result = ""
        test_url = target.rstrip("/") + "/druid/indexer/v1/sampler"
        
        # 使用无害的测试payload（不执行实际命令）
        payload = {
            "type": "index",
            "spec": {
                "ioConfig": {
                    "type": "index",
                    "inputSource": {
                        "type": "inline",
                        "data": "{\"test\":\"vulnerability_check\"}"
                    },
                    "inputFormat": {
                        "type": "json",
                        "keepNullColumns": True
                    }
                },
                "dataSchema": {
                    "dataSource": "sample",
                    "transformSpec": {
                        "filter": {
                            "type": "javascript",
                            "function": "function(value) {return true}",  # 无害函数
                            "dimension": "added"
                        }
                    }
                }
            }
        }
        
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                test_url,
                headers=headers,
                data=json.dumps(payload),
                verify=False,
                timeout=10
            )
            
            # 漏洞判断逻辑
            if response.status_code == 200:
                # 检查响应中是否包含特定错误特征
                if "javascript" in response.text.lower():
                    result = f"[{self.name}] 目标 {target}：存在CVE-2021-25646漏洞（可RCE）"
                else:
                    result = f"[{self.name}] 目标 {target}：可能存在CVE-2021-25646漏洞（需进一步验证）"
            elif response.status_code == 400 and "javascript" in response.text.lower():
                result = f"[{self.name}] 目标 {target}：可能存在CVE-2021-25646漏洞（但已被部分修复）"
            else:
                result = f"[{self.name}] 目标 {target}：未发现CVE-2021-25646漏洞"
                
        except requests.exceptions.Timeout:
            result = f"[{self.name}] 目标 {target}：检测超时"
        except requests.exceptions.ConnectionError:
            result = f"[{self.name}] 目标 {target}：连接失败"
        except Exception as e:
            result = f"[{self.name}] 目标 {target}：检测异常 - {str(e)}"
        
        return result