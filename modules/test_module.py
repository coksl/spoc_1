# 在 modules/ 目录下创建 test_module.py
class TestVuln:
    name = "测试漏洞"
    
    def check(self, target):
        return True, "测试成功"