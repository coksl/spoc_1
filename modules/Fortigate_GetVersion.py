import re
import gzip
import requests
import urllib3
from collections import defaultdict

urllib3.disable_warnings()

class FortigateVersionScanner:
    name = "Fortigate版本信息获取"
    description = "获取Fortigate防火墙的版本信息和特征哈希值"
    author = "未知"
    group = "信息收集"
    
    versionarray = [
        ["97a9a8eadad35e7c450cd9aae0848ee7", "7.2.3"],
        ["df91004ba8e5e244e7af97a888494774", "7.2.2"],
        ["4885e9396f0d5f343a31e82c0bc37c91", "7.2.1"],
        ["b911aeb68426644df64811a094b12f98", "7.0.6"],
    ]

    def __init__(self):
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.session.verify = False
        self.session.timeout = 10

    def version_scan(self, hash_value):
        """根据哈希值匹配Fortigate版本"""
        for value in self.versionarray:
            if hash_value == value[0]:
                return value[1]
        return "未知版本"

    def check(self, target, **kwargs):
        """执行Fortigate版本检测"""
        result = defaultdict(list)
        
        # 确保URL格式正确
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        if not target.endswith("/"):
            target += "/"
        
        try:
            response = self.session.get(target)
            
            if response.status_code == 200:
                # 处理重定向情况
                if "top.location=" in response.text:
                    redirect_match = re.compile(r"top.location=\"(.*?)\"")
                    redirect = redirect_match.findall(response.text)
                    
                    if redirect:
                        redirect_url = target + redirect[0]
                        result["redirect"] = redirect_url
                        response = self.session.get(redirect_url)
                
                # 处理gzip压缩内容
                if response.headers.get('Content-Encoding') == 'gzip':
                    content = gzip.decompress(response.content).decode('utf-8')
                else:
                    content = response.text
                
                # 查找哈希值
                hash_match = re.search(r'[0-9a-f]{32}', content)
                if hash_match:
                    hash_value = hash_match.group(0)
                    version = self.version_scan(hash_value)
                    
                    result["hash"] = hash_value
                    result["version"] = version
                    result["mode"] = "SSL VPN Client" if "redirect" in result else "Admin Management"
                    result["status"] = "存在漏洞" if version != "未知版本" else "版本未知"
                    
                    return f"[{self.name}] 目标: {target} - 模式: {result['mode']} - 哈希: {result['hash']} - 版本: {result['version']} - 状态: {result['status']}"
                else:
                    return f"[{self.name}] 目标: {target} - 未找到Fortigate特征哈希，可能是旧版本设备"
            else:
                return f"[{self.name}] 目标: {target} - 请求失败，状态码: {response.status_code}"
                
        except Exception as e:
            return f"[{self.name}] 目标: {target} - 检测异常: {str(e)}"

# 保留独立运行功能
if __name__ == "__main__":
    import sys
    scanner = FortigateVersionScanner()
    
    if len(sys.argv) != 2:
        print('Fortigate版本扫描模块')
        print('用法:')
        print(f'{sys.argv[0]} <目标URL>')
        print('示例:')
        print(f'{sys.argv[0]} https://192.168.1.1:4443/')
        sys.exit(0)
    
    target = sys.argv[1]
    print(scanner.check(target))