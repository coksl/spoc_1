import os
import importlib.util
import traceback
import sys  # 新增导入sys模块
from pathlib import Path

MODULES_DIR = Path(__file__).parent / "modules"
ALL_MODULES = []

def _extract_objects(module, group):
    objects = []
    for attr in dir(module):
        obj = getattr(module, attr)
        
        # 修复括号问题 - 使用更清晰的逻辑
        if not hasattr(obj, "name"):
            continue
        if not callable(getattr(obj, "check", None)):
            continue
        
        if isinstance(obj, type):
            obj = obj()  # 如果是类则实例化
        
        # 确保group属性存在
        if not hasattr(obj, 'group'):
            obj.group = group
        
        objects.append(obj)
    return objects

def load_modules(refresh=False):
    global ALL_MODULES
    if refresh:
        # 清除现有模块缓存
        ALL_MODULES.clear()
        
        # 新增：清除sys.modules中的缓存模块
        # 查找所有以"modules."开头的模块并删除
        modules_to_remove = [
            mod_name for mod_name in sys.modules 
            if mod_name.startswith("modules.")
        ]
        for mod_name in modules_to_remove:
            del sys.modules[mod_name]
    
    # 确保模块目录存在
    if not MODULES_DIR.exists():
        print(f"警告: 模块目录不存在 - {MODULES_DIR}")
        return
    
    # 遍历模块目录
    for root, dirs, files in os.walk(str(MODULES_DIR)):
        # 计算分组名称
        group = os.path.relpath(root, str(MODULES_DIR))
        if group == '.':
            group = "默认"
        
        for fname in files:
            # 跳过非Python文件、初始化文件和隐藏文件
            if not fname.endswith(".py"):
                continue
            if fname == "__init__.py":
                continue
            if fname.startswith("_"):
                continue
            
            mod_path = os.path.join(root, fname)
            
            # 生成模块名称
            try:
                rel_path = Path(mod_path).relative_to(MODULES_DIR)
                mod_name = f"modules.{rel_path.with_suffix('').as_posix().replace('/', '.')}"
            except ValueError:
                # 路径计算失败时使用简单名称
                mod_name = f"modules.{Path(fname).stem}"
            
            try:
                # 加载模块
                spec = importlib.util.spec_from_file_location(mod_name, mod_path)
                if spec is None:
                    print(f"警告: 无法为 {mod_path} 创建模块规范")
                    continue
                
                # 如果模块已加载且不是刷新模式，则跳过
                if not refresh and mod_name in sys.modules:
                    continue
                
                module = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = module  # 手动添加到sys.modules
                spec.loader.exec_module(module)
                
                # 提取符合条件的对象
                module_objects = _extract_objects(module, group)
                ALL_MODULES.extend(module_objects)
                
            except Exception as e:
                print(f"错误: 加载模块 {mod_name} 失败 - {str(e)}")
                traceback.print_exc()

# 初始加载
load_modules()