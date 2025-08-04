class ExampleVulnModule:
    name = "示例漏洞模块"
    description = "这是一个演示用的漏洞模块"
    author = "spoc团队"
    def check(self, target):
        # 检测逻辑
        return f"[{self.name}] 检测目标 {target}：未发现漏洞"
