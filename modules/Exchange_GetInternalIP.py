import re
import requests
import urllib3
from collections import defaultdict

urllib3.disable_warnings()

class ExchangeInternalIPScanner:
    name = "Exchange内部IP获取"
    description = "通过访问Exchange多个路径触发连接异常来获取内部IP"
    author = "未知"
    group = "信息收集"
    
    # 要尝试访问的Exchange路径
    url_paths = [
        "/OWA",
        "/Autodiscover",
        "/Exchange",
        "/ecp",
        "/aspnet_client"
    ]

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36",
            "Connection": "close"  # 确保每次请求后关闭连接
        })
        self.session.verify = False
        self.session.timeout = 5  # 设置较短的超时时间

    def check(self, target, **kwargs):
        """执行Exchange内部IP检测"""
        result = defaultdict(list)
        
        # 确保URL格式正确
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        if target.endswith("/"):
            target = target[:-1]
        
        result["target"] = target
        result["paths"] = self.url_paths
        
        try:
            for path in self.url_paths:
                url = target + path
                result["attempted_urls"].append(url)
                
                try:
                    response = self.session.get(url)
                    result["status_codes"].append(response.status_code)
                    
                    # 检查响应中是否已经暴露内部IP
                    internal_ip_match = re.search(r'\b(?:10(?:\.\d{1,3}){3}|(?:172\.(?:1[6-9]|2\d|3[01])|192\.168)(?:\.\d{1,3}){2}\b', response.text)
                    if internal_ip_match:
                        result["internal_ip"] = internal_ip_match.group(0)
                        return f"[{self.name}] 目标: {target} - 成功获取内部IP: {result['internal_ip']} (来自响应内容)"
                
                except requests.exceptions.ConnectionError as e:
                    # 从连接错误中提取内部IP
                    pattern = re.compile(r"host='(.*?)',")
                    ip_match = pattern.findall(str(e))
                    
                    if ip_match:
                        result["internal_ip"] = ip_match[0]
                        return f"[{self.name}] 目标: {target} - 成功获取内部IP: {result['internal_ip']} (来自连接错误)"
                
                except Exception as e:
                    result["errors"].append(str(e))
            
            # 如果所有路径都尝试过但未获取到IP
            if "internal_ip" not in result:
                return f"[{self.name}] 目标: {target} - 无法获取内部IP，尝试了 {len(self.url_paths)} 个路径"
                
        except Exception as e:
            return f"[{self.name}] 目标: {target} - 检测异常: {str(e)}"

# 保留独立运行功能
if __name__ == "__main__":
    import sys
    scanner = ExchangeInternalIPScanner()
    
    if len(sys.argv) != 2:
        print('Exchange内部IP获取模块')
        print('基于msf auxiliary/scanner/http/owa_iis_internal_ip，但支持更多Exchange服务器')
        print('用法:')
        print(f'{sys.argv[0]} <目标域名或IP>')
        print('示例:')
        print(f'{sys.argv[0]} mail.example.com')
        sys.exit(0)
    
    target = sys.argv[1]
    print(scanner.check(target))