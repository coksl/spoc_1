import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DellSonicWallVulnerability:
    name = "Dell SonicWall VPN 版本检测"
    description = "检测Dell SonicWall VPN设备的特定版本存在"
    author = "安全研究团队"
    group = "网络设备"
    severity = "中危"

    # 定义存在潜在漏洞的版本特征
    VULNERABLE_VERSIONS = {
        '9.0.0.10-28': 'swl_styles.9.0.0.10-28',
        '10.2.1.0-17': 'swl_styles.10.2.1.0-17'
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 10

    def check(self, target):
        """
        安全检测Dell SonicWall VPN设备版本
        :param target: 目标URL (如 https://example.com)
        :return: (bool, str) 漏洞存在性和详细结果
        """
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            # 构造检测URL
            test_url = f"{target.rstrip('/')}/cgi-bin/welcome"
            
            # 发送检测请求
            response = self.session.get(
                test_url,
                timeout=self.timeout,
                allow_redirects=False
            )

            # 检查响应是否有效
            if response.status_code != 200:
                return False, f"[{self.name}] 目标 {target} 无法访问欢迎页面 (HTTP {response.status_code})"

            response_text = response.text
            
            # 检查是否存在漏洞版本特征
            detected_versions = []
            for version, signature in self.VULNERABLE_VERSIONS.items():
                if signature in response_text:
                    detected_versions.append(version)

            if detected_versions:
                versions_str = ", ".join(detected_versions)
                return True, f"[{self.name}] 目标 {target} 检测到潜在漏洞版本: {versions_str}"
            else:
                return False, f"[{self.name}] 目标 {target} 未检测到已知漏洞版本"

        except requests.Timeout:
            return False, f"[{self.name}] 目标 {target} 检测超时"
        except requests.SSLError:
            return False, f"[{self.name}] 目标 {target} SSL证书错误"
        except requests.ConnectionError:
            return False, f"[{self.name}] 目标 {target} 连接失败"
        except Exception as e:
            return False, f"[{self.name}] 目标 {target} 检测异常: {str(e)}"