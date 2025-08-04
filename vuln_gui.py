import sys
import os
import shutil
import json
from collections import defaultdict
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QDialog,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QFileDialog, QMessageBox, QScrollArea, QSizePolicy, QGridLayout, QAction
)
from PyQt5.QtGui import QTextCursor, QColor, QFont, QIcon, QPalette
from PyQt5.QtCore import Qt, pyqtSignal, QThreadPool, QRunnable, QObject
from vuln_modules import ALL_MODULES, load_modules, MODULES_DIR

MODULE_GUIDE = """
# 漏洞模块开发规范

1. 每个模块为一个独立的.py文件，放置于modules目录下
2. 必须实现name属性（字符串）和check(self, **kwargs)方法
3. 可以通过定义required_params列表指定需要的参数
4. 推荐使用JSON配置文件传递参数

示例模块：
class MyVulnModule:
    name = "示例漏洞模块"
    required_params = ["param1", "param2"]
    
    def check(self, target, param1=None, param2=None, **kwargs):
        return f"[{self.name}] 检测结果: target={target}, param1={param1}, param2={param2}"
"""

class LogSignal(QObject):
    """日志信号类，用于线程间通信"""
    log = pyqtSignal(str, object)  # str: 日志内容, object: 颜色

class ScanTask(QRunnable):
    """扫描任务类，在后台线程中执行扫描"""
    def __init__(self, params, modules, log_signal):
        """
        初始化扫描任务
        
        :param params: 扫描参数
        :param modules: 要执行的模块列表
        :param log_signal: 日志信号对象
        """
        super().__init__()
        self.params = params
        self.modules = modules
        self.log_signal = log_signal

    def run(self):
        """执行扫描任务的主方法"""
        # 处理文件目标
        if 'target_file' in self.params:
            try:
                with open(self.params['target_file'], 'r', encoding='utf-8') as f:
                    targets = [line.strip() for line in f if line.strip()]
                for target in targets:
                    self.process_target(target)
            except Exception as e:
                self.log_signal.log.emit(f"读取目标文件失败: {str(e)}", QColor(255, 0, 0))
        # 处理单个URL目标
        elif 'target' in self.params:
            self.process_target(self.params['target'])
        else:
            self.log_signal.log.emit("没有有效的目标输入", QColor(255, 0, 0))
        
        self.log_signal.log.emit("检测完成。\n", None)

    def process_target(self, target):
        """处理单个目标"""
        self.log_signal.log.emit(f"开始检测目标：{target}", None)
        for module in self.modules:
            self.log_signal.log.emit(f"[*] 检测模块：{module.name}", None)
            try:
                module_params = self.params.copy()
                module_params['target'] = target
            
                # 修复：检查模块配置是否是字典类型
                if 'modules' in module_params:
                    module_config = module_params['modules'].get(module.name, {})
                    # 确保配置是字典类型且包含 'params'
                    if isinstance(module_config, dict) and 'params' in module_config:
                        module_params.update(module_config['params'])
            
                result = module.check(**module_params)
                if "存在漏洞" in result:
                    self.log_signal.log.emit(result, QColor(0, 255, 0))  # 绿色显示漏洞
                else:
                    self.log_signal.log.emit(result, None)  # 默认颜色
            except Exception as e:
                self.log_signal.log.emit(f"[{module.name}] 检测异常：{e}", None)  # 异常日志
            
class CollapsibleGroupBox(QGroupBox):
    """可折叠的组框控件"""
    def __init__(self, title="", parent=None):
        """
        初始化可折叠组框
        
        :param title: 组框标题
        :param parent: 父控件
        """
        super().__init__(title, parent)
        self.setCheckable(True)  # 设置为可勾选
        self.setChecked(True)    # 默认展开
        self.toggled.connect(self.on_toggle)  # 连接切换信号
        
        # 创建内容区域
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(15, 20, 15, 15)
        
        # 主布局
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.content_widget)
        
        # 初始状态
        self.content_widget.setVisible(True)
        
        # 设置箭头样式
        self.setStyleSheet("""
            QGroupBox::indicator {
                width: 15px;
                height: 15px;
                padding: 0px;
            }
            QGroupBox::indicator:checked {
                image: url(:/icons/down_arrow.png);
            }
            QGroupBox::indicator:unchecked {
                image: url(:/icons/right_arrow.png);
            }
        """)
        
        # 设置大小策略确保折叠时不影响布局
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
    
    def on_toggle(self, checked):
        """切换折叠状态"""
        self.content_widget.setVisible(checked)
        # 通知布局重新计算
        if self.parent():
            self.parent().updateGeometry()
    
    def addWidget(self, widget):
        """添加控件到内容区域"""
        self.content_layout.addWidget(widget)
    
    def addLayout(self, layout):
        """添加布局到内容区域"""
        self.content_layout.addLayout(layout)

class VulnGUI(QWidget):
    """漏洞扫描框架主界面"""
    def __init__(self):
        super().__init__()
        print(f"Initializing GUI... Modules directory: {MODULES_DIR}")  # 调试输出
        print(f"Loaded modules: {len(ALL_MODULES)}")  # 调试输出
        self.setWindowTitle("漏洞扫描框架(JSON配置版)")
        self.resize(1000, 750)  # 增加窗口大小
        self.thread_pool = QThreadPool()
        self.log_signal = LogSignal()
        self.log_signal.log.connect(self.append_log)
        self.module_search_text = ""
        self.current_config = None
        self.module_checks = []
        self.current_module = None
        self.init_ui()
    
    def append_log(self, text, color=None):
        """添加日志到日志框，支持颜色设置"""
        cursor = self.log_box.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        if color:
            # 设置带颜色的文本
            self.log_box.setTextColor(color)
        else:
            # 使用默认颜色（来自样式表）
            self.log_box.setTextColor(QColor('#e0e0e0'))
            
        cursor.insertText(text + "\n")
        self.log_box.setTextCursor(cursor)
        self.log_box.ensureCursorVisible()
    
    def on_search_text_changed(self, text):
        """处理模块搜索框文本变化事件"""
        self.module_search_text = text.strip().lower()
        self.refresh_modules()
    
    def refresh_modules(self):
        """刷新显示模块列表（支持搜索过滤）"""
        try:
            print("Refreshing module list...")  # 调试输出
            print(f"Total modules available: {len(ALL_MODULES)}")  # 调试输出
            
            # 清空现有模块列表
            for i in reversed(range(self.module_list_layout.count())):
                widget = self.module_list_layout.itemAt(i).widget()
                if widget:
                    widget.setParent(None)
            self.module_checks.clear()

            # 如果没有加载到任何模块，显示提示信息
            if not ALL_MODULES:
                label = QLabel("没有可用的模块或加载模块失败")
                label.setStyleSheet("color: #dc3545; font-weight: bold; font-size: 13px;")
                label.setAlignment(Qt.AlignCenter)
                self.module_list_layout.addWidget(label)
                print("No modules loaded!")  # 调试输出
                return

            # 按分组组织模块
            group_dict = defaultdict(list)
            for module in ALL_MODULES:
                group = getattr(module, "group", "默认")
                group_dict[group].append(module)

            # 应用搜索过滤
            search_term = self.module_search_text
            for group, modules in group_dict.items():
                # 过滤模块
                filtered = [
                    mod for mod in modules
                    if not search_term or 
                    search_term in f"{mod.name} {getattr(mod,'description','')} {getattr(mod,'author','')}".lower()
                ]
                if not filtered:
                    continue

                # 添加分组标签
                group_label = QLabel(f"【{group}】")
                group_label.setStyleSheet("""
                    font-weight: bold; 
                    color: #1a73e8; 
                    font-size: 13px;
                    margin-top: 10px;
                    padding-bottom: 5px;
                    border-bottom: 1px solid #e0e0e0;
                """)
                self.module_list_layout.addWidget(group_label)

                # 添加模块复选框
                for module in filtered:
                    cb = QCheckBox(self.format_module_info(module))
                    cb.setStyleSheet("""
                        QCheckBox {
                            background-color: #ffffff;
                            padding: 10px;
                            border-radius: 4px;
                            margin: 3px 0;
                            font-size: 12px;
                            color: #333333;
                        }
                        QCheckBox:hover {
                            background-color: #f1f8ff;
                        }
                        QCheckBox::indicator {
                            width: 16px;
                            height: 16px;
                        }
                        QCheckBox::indicator:checked {
                            background-color: #1a73e8;
                            border: 1px solid #1a73e8;
                        }
                    """)
                    cb.module = module  # 附加模块对象
                    cb.clicked.connect(lambda _, m=module: self.on_module_selected(m))
                    self.module_list_layout.addWidget(cb)
                    self.module_checks.append(cb)

            self.module_list_layout.addStretch()  # 添加弹性空间
            print(f"Module list refreshed. Displaying {len(self.module_checks)} modules.")  # 调试输出
        except Exception as e:
            print(f"Error refreshing modules: {str(e)}")  # 调试输出
            QMessageBox.critical(self, "错误", f"刷新模块失败: {str(e)}")

    def init_ui(self):
        """初始化用户界面"""
        try:
            print("Initializing UI components...")  # 调试输出
            main_layout = QVBoxLayout()
            main_layout.setSpacing(15)
            main_layout.setContentsMargins(20, 20, 20, 20)

            # ==============================================================
            # 顶部控制区域 - 包含三个部分：配置文件管理、目标输入、模块筛选
            # ==============================================================
            top_layout = QHBoxLayout()
            top_layout.setSpacing(20)
            
            # 配置文件管理区域 - 可折叠组框
            config_group = CollapsibleGroupBox("配置文件管理")
            config_group.setStyleSheet("font-size: 13px;")
            config_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)  # 添加高度策略
            
            # 配置文件信息显示
            config_info_layout = QHBoxLayout()
            config_info_layout.addWidget(QLabel("当前配置:"))
            self.config_info_label = QLabel("未加载配置文件")
            self.config_info_label.setStyleSheet("""
                font-weight: bold; 
                color: #1a73e8;
                font-size: 13px;
            """)
            self.config_info_label.setWordWrap(True)
            config_info_layout.addWidget(self.config_info_label, 1)
            config_group.addLayout(config_info_layout)
            
            # 配置文件操作按钮
            btn_layout = QGridLayout()
            btn_layout.setHorizontalSpacing(10)
            btn_layout.setVerticalSpacing(10)
            
            # 加载配置按钮
            load_btn = QPushButton("加载配置")
            load_btn.setIcon(QIcon.fromTheme("document-open"))
            load_btn.setToolTip("从JSON文件加载扫描配置")
            load_btn.setFixedHeight(40)
            load_btn.setStyleSheet("font-size: 12px;")
            load_btn.clicked.connect(self.load_json_config)
            
            # 保存配置按钮
            self.save_btn = QPushButton("保存配置")
            self.save_btn.setIcon(QIcon.fromTheme("document-save"))
            self.save_btn.setToolTip("保存当前配置到JSON文件")
            self.save_btn.setFixedHeight(40)
            self.save_btn.setEnabled(False)  # 初始禁用
            self.save_btn.setStyleSheet("font-size: 12px;")
            self.save_btn.clicked.connect(self.save_json_config)
            
            # 生成模板按钮
            template_btn = QPushButton("生成模板")
            template_btn.setIcon(QIcon.fromTheme("document-new"))
            template_btn.setToolTip("创建新的配置文件模板")
            template_btn.setFixedHeight(40)
            template_btn.setStyleSheet("font-size: 12px;")
            template_btn.clicked.connect(self.generate_template)
            
            # 配置编辑按钮
            self.edit_btn = QPushButton("编辑配置")
            self.edit_btn.setIcon(QIcon.fromTheme("accessories-text-editor"))
            self.edit_btn.setToolTip("编辑当前配置")
            self.edit_btn.setFixedHeight(40)
            self.edit_btn.setEnabled(False)  # 初始禁用
            self.edit_btn.setStyleSheet("font-size: 12px;")
            self.edit_btn.clicked.connect(self.edit_config)
            
            # 添加到布局 - 使用网格布局确保按钮大小一致
            btn_layout.addWidget(load_btn, 0, 0)
            btn_layout.addWidget(self.save_btn, 0, 1)
            btn_layout.addWidget(template_btn, 1, 0)
            btn_layout.addWidget(self.edit_btn, 1, 1)
            
            config_group.addLayout(btn_layout)
            top_layout.addWidget(config_group)
            # ==============================================================

            # 目标输入区域 - 优化后的简洁设计
            target_group = QGroupBox("扫描目标")
            target_group.setStyleSheet("font-size: 13px;")
            target_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)  # 添加高度策略
            target_layout = QVBoxLayout()
            target_layout.setSpacing(10)  # 减少间距
            target_layout.setContentsMargins(15, 15, 15, 15)  # 调整边距
            
            # URL输入框 - 简洁优化
            url_layout = QHBoxLayout()
            url_layout.addWidget(QLabel("目标 URL:"))
            self.target_input = QLineEdit()
            self.target_input.setPlaceholderText("http://example.com")
            self.target_input.setFixedHeight(36)  # 稍降低高度
            self.target_input.setStyleSheet("""
                font-size: 13px;
                padding: 6px 10px;
                border-radius: 4px;
                background-color: #ffffff;
                color: #333333;
            """)
            url_layout.addWidget(self.target_input, 1)  # 添加弹性空间使输入框扩展
            target_layout.addLayout(url_layout)
            
            # 文件导入按钮 - 简洁优化
            file_layout = QHBoxLayout()
            file_layout.addWidget(QLabel("目标文件:"))
            self.file_path_label = QLabel("未选择文件")
            self.file_path_label.setStyleSheet("""
                font-size: 12px;
                color: #5f6368;
                background-color: #ffffff;
                border: 1px solid #dadce0;
                border-radius: 4px;
                padding: 8px 12px;
                min-height: 36px;
            """)
            self.file_path_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            
            file_btn = QPushButton("选择")
            file_btn.setIcon(QIcon.fromTheme("document-import"))
            file_btn.setFixedSize(70, 36)  # 更紧凑的按钮
            file_btn.setStyleSheet("""
                font-size: 12px;
                padding: 0px 5px;
            """)
            file_btn.clicked.connect(self.import_target_file)
            
            file_layout.addWidget(self.file_path_label, 1)  # 添加弹性空间使标签扩展
            file_layout.addWidget(file_btn)
            target_layout.addLayout(file_layout)
            
            target_group.setLayout(target_layout)
            top_layout.addWidget(target_group)
            # ==============================================================

            # 模块筛选区域 - 优化设计（标签和输入框上下平行显示）
            search_group = QGroupBox("模块筛选")
            search_group.setStyleSheet("""
                QGroupBox {
                    font-size: 13px;
                    font-weight: bold;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    margin-top: 0px;
                    padding-top: 15px;
                    background-color: #ffffff;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top center;  /* 改为居中 */
                    padding: 0 8px;
                    color: #5f6368;
                }
            """)
            search_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)  # 添加高度策略
            
            # 使用垂直布局使标签和输入框上下平行显示
            search_layout = QVBoxLayout()
            search_layout.setSpacing(8)  # 标签和输入框之间的间距
            search_layout.setContentsMargins(15, 15, 15, 15)  # 与目标区域一致
            
            # 搜索标签 - 上方显示
            search_label = QLabel("🔍 搜索模块")
            search_label.setStyleSheet("""
                QLabel {
                    font-size: 14px;
                    font-weight: 600;
                    color: #5f6368;
                    padding: 5px 0;
                    text-align: center;  /* 文本居中 */
                }
            """)
            search_label.setAlignment(Qt.AlignCenter)  # 标签居中
            search_layout.addWidget(search_label)
            
            # 搜索输入框 - 下方显示
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("输入模块名称、描述或作者...")
            self.search_input.setFixedHeight(42)
            self.search_input.setStyleSheet("""
                QLineEdit {
                    font-size: 14px;
                    padding: 10px 20px 10px 45px;
                    border-radius: 21px;
                    background-color: #ffffff;
                    border: 2px solid #e0e0e0;
                    color: #202124;
                    font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
                }
                QLineEdit:hover {
                    border-color: #cbd5e0;
                    background-color: #f8f9fa;
                }
                QLineEdit:focus {
                    border-color: #1a73e8;
                    background-color: #ffffff;
                    box-shadow: 0 0 0 2px rgba(26, 115, 232, 0.2);
                }
            """)
            
            # 添加搜索图标
            search_action = QAction(self)
            search_icon = QIcon.fromTheme("edit-find", QIcon(":/icons/search.svg"))
            if not search_icon.isNull():
                search_action.setIcon(search_icon)
                self.search_input.addAction(search_action, QLineEdit.LeadingPosition)
            
            # 连接信号
            self.search_input.textChanged.connect(self.on_search_text_changed)
            
            # 添加到布局
            search_layout.addWidget(self.search_input)
            
            # 添加清除按钮
            self.search_input.setClearButtonEnabled(True)
            self.search_input.setStyleSheet(self.search_input.styleSheet() + """
                QLineEdit::clear-button {
                    icon-size: 16px;
                    subcontrol-position: right center;
                    right: 12px;
                }
            """)
            
            search_group.setLayout(search_layout)
            top_layout.addWidget(search_group)
            # ==============================================================

            # 设置三个组框的拉伸因子相同，确保宽度均匀分配
            top_layout.setStretchFactor(config_group, 1)
            top_layout.setStretchFactor(target_group, 1)
            top_layout.setStretchFactor(search_group, 1)

            main_layout.addLayout(top_layout)

            # 模块区域
            module_layout = QVBoxLayout()
            
            # 模块列表区域（带滚动条）
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.NoFrame)
            
            self.module_list_group = QGroupBox("可用模块")
            self.module_list_group.setStyleSheet("""
                QGroupBox {
                    background-color: #ffffff;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    margin-top: 10px;
                    padding: 15px 10px;
                    font-size: 13px;
                }
            """)
            self.module_list_layout = QVBoxLayout()
            self.module_list_layout.setSpacing(10)
            self.module_list_layout.setContentsMargins(15, 15, 15, 15)
            
            self.module_list_group.setLayout(self.module_list_layout)
            scroll.setWidget(self.module_list_group)
            
            module_layout.addWidget(scroll)
            main_layout.addLayout(module_layout, 3)  # 分配更多空间

            # 操作按钮区域
            btn_group = QGroupBox()
            btn_layout = QHBoxLayout()
            btn_layout.setSpacing(20)
            btn_layout.setContentsMargins(20, 10, 20, 10)
            
            self.add_module_btn = QPushButton("添加模块")
            self.add_module_btn.setIcon(QIcon.fromTheme("list-add"))
            self.add_module_btn.setFixedSize(150, 45)
            self.add_module_btn.setStyleSheet("font-size: 12px;")
            self.add_module_btn.clicked.connect(self.add_module)
            
            self.download_guide_btn = QPushButton("开发指南")
            self.download_guide_btn.setIcon(QIcon.fromTheme("help-contents"))
            self.download_guide_btn.setFixedSize(150, 45)
            self.download_guide_btn.setStyleSheet("font-size: 12px;")
            self.download_guide_btn.clicked.connect(self.download_guide)
            
            self.clear_btn = QPushButton("清空配置")
            self.clear_btn.setIcon(QIcon.fromTheme("edit-clear"))
            self.clear_btn.setFixedSize(150, 45)
            self.clear_btn.setStyleSheet("font-size: 12px;")
            self.clear_btn.clicked.connect(self.clear_config)
            
            self.start_btn = QPushButton("开始扫描")
            self.start_btn.setIcon(QIcon.fromTheme("media-playback-start"))
            self.start_btn.setFixedSize(150, 45)
            self.start_btn.setStyleSheet("""
                background-color: #1a73e8; 
                color: white; 
                font-weight: bold;
                font-size: 13px;
                border-radius: 6px;
            """)
            self.start_btn.clicked.connect(self.start_scan)
            
            btn_layout.addStretch()
            btn_layout.addWidget(self.add_module_btn)
            btn_layout.addWidget(self.download_guide_btn)
            btn_layout.addWidget(self.clear_btn)
            btn_layout.addWidget(self.start_btn)
            btn_layout.addStretch()
            
            btn_group.setLayout(btn_layout)
            main_layout.addWidget(btn_group)

            # 日志区域
            log_group = QGroupBox("扫描日志")
            log_group.setStyleSheet("font-size: 13px;")
            log_layout = QVBoxLayout()
            self.log_box = QTextEdit()
            self.log_box.setReadOnly(True)
            self.log_box.setStyleSheet("""
                background-color: #1e1e1e; 
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 5px;
                padding: 12px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            """)
            log_layout.addWidget(self.log_box)
            log_group.setLayout(log_layout)
            main_layout.addWidget(log_group, 2)  # 分配较少空间

            # 设置全局样式
            self.setStyleSheet("""
                QWidget {
                    background-color: #f5f7fa;
                    font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
                    color: #333333;
                }
                QGroupBox {
                    font-size: 14px;
                    font-weight: bold;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    margin-top: 10px;
                    padding: 15px 10px;
                    background-color: white;
                    color: #5f6368;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    subcontrol-position: top center;
                    padding: 0 5px;
                }
                QLabel {
                    font-size: 13px;
                    color: #5f6368;
                }
                QPushButton {
                    background-color: #f8f9fa;
                    border: 1px solid #dadce0;
                    border-radius: 6px;
                    padding: 8px 15px;
                    min-width: 80px;
                    font-weight: 500;
                    font-size: 12px;
                    color: #202124;
                }
                QPushButton:hover {
                    background-color: #f1f3f4;
                    border-color: #cbd5e0;
                }
                QPushButton:pressed {
                    background-color: #e8eaed;
                }
                QLineEdit {
                    border: 1px solid #dadce0;
                    border-radius: 6px;
                    padding: 8px 12px;
                    background-color: white;
                    font-size: 12px;
                    color: #202124;
                }
                QScrollArea {
                    border: none;
                    background-color: transparent;
                }
                QCheckBox {
                    spacing: 10px;
                    font-size: 12px;
                    color: #333333;
                }
                QTextEdit {
                    border: 1px solid #dadce0;
                    border-radius: 6px;
                    background-color: white;
                    font-size: 12px;
                    color: #333333;
                }
                /* 优化文件路径标签 */
                QLabel#filePathLabel {
                    background-color: #ffffff;
                    border: 1px solid #dadce0;
                    border-radius: 4px;
                    padding: 8px 12px;
                    color: #5f6368;
                }
            """)
            
            # 为文件路径标签设置对象名以便样式表定位
            self.file_path_label.setObjectName("filePathLabel")

            self.setLayout(main_layout)  # 确保设置主布局
            print("UI components initialized. Refreshing modules...")  # 调试输出
            self.refresh_modules()
            print("UI initialization complete.")  # 调试输出
        except Exception as e:
            print(f"Error during UI initialization: {str(e)}")  # 调试输出
            QMessageBox.critical(self, "UI初始化错误", f"界面初始化失败: {str(e)}")
    
    def format_module_info(self, module):
        """格式化模块信息显示"""
        info = module.name
        if hasattr(module, 'description'):
            info += f" - {module.description}"
        if hasattr(module, 'author'):
            info += f" (作者: {module.author})"
        return info
    
    def on_module_selected(self, module):
        """当模块被选中时触发"""
        self.current_module = module
        print(f"Selected module: {module.name}")
    
    def load_json_config(self):
        """加载JSON配置文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "加载配置文件", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.current_config = config
            self.config_info_label.setText(os.path.basename(file_path))
            self.save_btn.setEnabled(True)
            self.edit_btn.setEnabled(True)
            
            # 设置目标
            if 'target' in config:
                self.target_input.setText(config['target'])
            
            # 设置目标文件
            if 'target_file' in config:
                self.file_path_label.setText(os.path.basename(config['target_file']))
            
            self.append_log(f"配置文件加载成功: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "加载错误", f"无法加载配置文件: {str(e)}")
            self.append_log(f"配置文件加载失败: {str(e)}", QColor(255, 0, 0))
    
    def save_json_config(self):
        """保存当前配置到JSON文件"""
        if not self.current_config:
            QMessageBox.warning(self, "保存失败", "没有可保存的配置")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存配置文件", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.current_config, f, indent=4, ensure_ascii=False)
            
            self.append_log(f"配置文件保存成功: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "保存错误", f"无法保存配置文件: {str(e)}")
            self.append_log(f"配置文件保存失败: {str(e)}", QColor(255, 0, 0))
    
    def generate_template(self):
        """生成配置文件模板"""
        template = {
            "target": "http://example.com",
            "target_file": "targets.txt",
            "modules": {
                "模块名称": {
                    "enabled": True,
                    "params": {
                        "param1": "value1",
                        "param2": "value2"
                    }
                }
            }
        }
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存配置文件模板", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(template, f, indent=4, ensure_ascii=False)
            
            self.append_log(f"配置文件模板生成成功: {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "生成错误", f"无法生成配置文件模板: {str(e)}")
            self.append_log(f"配置文件模板生成失败: {str(e)}", QColor(255, 0, 0))
    
    def edit_config(self):
        """编辑当前配置"""
        if not self.current_config:
            QMessageBox.warning(self, "编辑失败", "没有可编辑的配置")
            return
        
        try:
            # 在文本框中显示当前配置
            dialog = QDialog(self)
            dialog.setWindowTitle("编辑配置")
            dialog.resize(600, 400)
            
            layout = QVBoxLayout()
            text_edit = QTextEdit()
            text_edit.setPlainText(json.dumps(self.current_config, indent=4, ensure_ascii=False))
            text_edit.setFont(QFont("Consolas", 10))
            
            btn_box = QHBoxLayout()
            save_btn = QPushButton("保存")
            save_btn.clicked.connect(lambda: self.save_edited_config(text_edit.toPlainText(), dialog))
            cancel_btn = QPushButton("取消")
            cancel_btn.clicked.connect(dialog.reject)
            
            btn_box.addStretch()
            btn_box.addWidget(save_btn)
            btn_box.addWidget(cancel_btn)
            
            layout.addWidget(text_edit)
            layout.addLayout(btn_box)
            dialog.setLayout(layout)
            
            dialog.exec_()
            
        except Exception as e:
            QMessageBox.critical(self, "编辑错误", f"配置编辑失败: {str(e)}")
    
    def save_edited_config(self, text, dialog):
        """保存编辑后的配置"""
        try:
            config = json.loads(text)
            self.current_config = config
            dialog.accept()
            self.append_log("配置编辑成功")
        except json.JSONDecodeError as e:
            QMessageBox.critical(self, "格式错误", f"无效的JSON格式: {str(e)}")
    
    def import_target_file(self):
        """导入目标文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            self.file_path_label.setText(os.path.basename(file_path))
            self.append_log(f"目标文件已导入: {file_path}")
    
    def add_module(self):
        """添加新模块"""
        # 在实际应用中，这里应该实现添加新模块的功能
        # 例如，打开文件对话框选择模块文件，然后复制到模块目录
        QMessageBox.information(self, "添加模块", "此功能尚未实现")
    
    def download_guide(self):
        """下载模块开发指南"""
        # 在实际应用中，这里应该提供模块开发指南的下载
        # 例如，打开浏览器或显示帮助文档
        dialog = QDialog(self)
        dialog.setWindowTitle("模块开发指南")
        dialog.resize(500, 400)
        
        layout = QVBoxLayout()
        text_edit = QTextEdit()
        text_edit.setMarkdown(MODULE_GUIDE)
        text_edit.setReadOnly(True)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(dialog.accept)
        
        layout.addWidget(text_edit)
        layout.addWidget(close_btn)
        dialog.setLayout(layout)
        
        dialog.exec_()
    
    def clear_config(self):
        """清空当前配置"""
        self.current_config = None
        self.config_info_label.setText("未加载配置文件")
        self.target_input.clear()
        self.file_path_label.setText("未选择文件")
        self.save_btn.setEnabled(False)
        self.edit_btn.setEnabled(False)
        self.append_log("配置已清空")
    
    def start_scan(self):
        """开始扫描"""
        # 收集参数
        params = {}
        
        # 获取目标URL
        target = self.target_input.text().strip()
        if target:
            params['target'] = target
        
        # 获取目标文件
        file_path = self.file_path_label.text()
        if file_path != "未选择文件":
            params['target_file'] = file_path
        
        # 如果没有目标，显示错误
        if not params.get('target') and not params.get('target_file'):
            QMessageBox.critical(self, "扫描错误", "请指定目标URL或目标文件")
            return
        
        # 收集选中的模块
        selected_modules = []
        for cb in self.module_checks:
            if cb.isChecked():
                selected_modules.append(cb.module)
        
        if not selected_modules:
            QMessageBox.critical(self, "扫描错误", "请选择至少一个检测模块")
            return
        
        # 清空日志
        self.log_box.clear()
        
        # 创建并运行扫描任务
        task = ScanTask(params, selected_modules, self.log_signal)
        self.thread_pool.start(task)
        self.append_log("开始扫描任务...")

def main():
    """主函数，启动应用程序"""
    app = QApplication(sys.argv)
    
    # 设置应用字体 - 使用通用字体族
    font = QFont()
    font.setFamily("Microsoft YaHei, Segoe UI, PingFang SC, sans-serif")
    font.setPointSize(10)
    app.setFont(font)
    
    # 设置高DPI支持
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    try:
        print("Creating GUI instance...")  # 调试输出
        gui = VulnGUI()
        print("Showing GUI...")  # 调试输出
        gui.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Fatal error: {str(e)}")  # 调试输出
        QMessageBox.critical(None, "致命错误", f"应用程序启动失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()