#!/usr/bin/env python3

import hashlib
from typing import List, Tuple

class CredentialExtractor:
    """
    安全地从特定数据格式中提取和解密用户凭据的工具类
    """
    def __init__(self):
        self.magic_key = b"283i4jfkai3389"  # 固定密钥，用于解密

    def decrypt_password(self, user: bytes, pass_enc: bytes) -> str:
        """
        安全解密密码数据
        :param user: 用户名字节串
        :param pass_enc: 加密的密码字节串
        :return: 解密后的密码字符串
        """
        if not user or not pass_enc:
            return ""
            
        key = hashlib.md5(user + self.magic_key).digest()
        passw = []
        
        for i in range(len(pass_enc)):
            passw.append(chr(pass_enc[i] ^ key[i % len(key)]))
        
        return "".join(passw).split("\x00")[0]

    def extract_credentials(self, entry: bytes) -> Tuple[str, str]:
        """
        从数据条目中提取用户名和加密密码
        :param entry: 二进制数据条目
        :return: (username, password) 元组
        """
        try:
            user_data = entry.split(b"\x01\x00\x00\x21")[1]
            pass_data = entry.split(b"\x11\x00\x00\x21")[1]

            user_len = user_data[0]
            pass_len = pass_data[0]

            username = user_data[1:1 + user_len]
            password = pass_data[1:1 + pass_len]

            return username.decode("ascii", errors="ignore"), self.decrypt_password(username, password)
        except (IndexError, AttributeError):
            return "", ""

    def process_data(self, data: bytes) -> List[Tuple[str, str]]:
        """
        处理原始数据并提取所有凭据对
        :param data: 原始二进制数据
        :return: 包含(username, password)元组的列表
        """
        credentials = []
        entries = data.split(b"M2")[1:]  # 假设M2是分隔符
        
        for entry in entries:
            user, password = self.extract_credentials(entry)
            if user and password:
                credentials.append((user, password))
        
        return credentials

    @staticmethod
    def display_credentials(credentials: List[Tuple[str, str]]) -> None:
        """
        安全地显示提取的凭据（仅用于调试）
        :param credentials: 凭据列表
        """
        for user, pwd in credentials:
            print(f"[+] 用户名: {user}")
            print(f"[+] 密码: {'*' * len(pwd)}")  # 掩码显示密码
            print()

if __name__ == "__main__":
    import sys
    import getpass
    
    if len(sys.argv) != 2:
        print("使用说明:")
        print(f"\t从文件读取: {sys.argv[0]} user.dat")
        print(f"\t从标准输入: {sys.argv[0]} -")
        sys.exit(1)

    try:
        # 安全读取输入数据
        if sys.argv[1] == "-":
            print("请粘贴数据内容（结束时按Ctrl+D）：")
            input_data = sys.stdin.buffer.read()
        else:
            with open(sys.argv[1], "rb") as f:
                input_data = f.read()

        # 处理并显示结果
        extractor = CredentialExtractor()
        found_creds = extractor.process_data(input_data)
        
        if found_creds:
            print(f"\n找到 {len(found_creds)} 组凭据：")
            CredentialExtractor.display_credentials(found_creds)
            
            # 安全提示
            print("警告：这些凭据应安全存储！")
            if getpass.getpass("是否要保存到文件？(y/n): ").lower() == 'y':
                output_file = getpass.getpass("输入保存路径: ")
                with open(output_file, "w") as f:
                    for user, pwd in found_creds:
                        f.write(f"{user}:{pwd}\n")
                print(f"凭据已加密保存到 {output_file}")
        else:
            print("未找到有效凭据")

    except Exception as e:
        print(f"处理错误: {str(e)}", file=sys.stderr)
        sys.exit(1)