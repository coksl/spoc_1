from vuln_gui import main

if __name__ == "__main__":
    main()
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QCheckBox, QGroupBox,
    QFileDialog, QMessageBox
from PyQt5.QtGui import QTextCursor, QColor
from PyQt5.QtCore import Qt, pyqtSignal, QThreadPool, QRunnable, QObject
from vuln_modules import ALL_MODULES, load_modules, MODULES_DIR

MODULE_GUIDE = """
# 漏洞模块开发规范

1. 每个模块为一个独立的 .py 文件，放置于 modules 目录下。
2. 必须实现 name 属性（字符串）和 check(self, target) 方法。
3. check 方法参数 target 为字符串，返回检测结果字符串。
4. 推荐以类方式实现。例如：

class MyVulnModule:
    name = "自定义漏洞模块"
    def check(self, target):
        # 检测逻辑
        return f"[{self.name}] 检测目标 {target}：未发现漏洞"

# 也支持直接定义对象：
class AnotherModule:
    name = "另一个模块"
    def check(self, target):
        return f"[{self.name}] 检测目标 {target}：存在漏洞"

module = AnotherModule()
"""

class LogSignal(QObject):
    log = pyqtSignal(str, object)  # str, color

class ScanTask(QRunnable):
    def __init__(self, target, modules, log_signal):
        super().__init__()
        self.target = target
        self.modules = modules
        self.log_signal = log_signal

    def run(self):
        self.log_signal.log.emit(f"开始检测目标：{self.target}", None)
        for module in self.modules:
            self.log_signal.log.emit(f"[*] 检测模块：{module.name}", None)
            try:
                result = module.check(self.target)
                if "存在漏洞" in result:
                    self.log_signal.log.emit(result, QColor(0, 255, 0))
                else:
                    self.log_signal.log.emit(result, None)
            except Exception as e:
                self.log_signal.log.emit(f"[{module.name}] 检测异常：{e}", None)
        self.log_signal.log.emit("检测完成。\n", None)

class VulnGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("漏洞利用框架")
        self.resize(500, 400)
        self.thread_pool = QThreadPool()
        self.log_signal = LogSignal()
        self.log_signal.log.connect(self.append_log)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # 目标输入
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("目标:"))
        self.target_input = QLineEdit()
        target_layout.addWidget(self.target_input)
        # 添加导入TXT按钮
        self.import_btn = QPushButton("导入TXT")
        self.import_btn.clicked.connect(self.import_targets_from_txt)
        target_layout.addWidget(self.import_btn)
        layout.addLayout(target_layout)

        # 添加模块按钮（放在选择模块前面）
        btn_layout = QHBoxLayout()
        self.add_module_btn = QPushButton("添加模块")
        self.add_module_btn.clicked.connect(self.add_module)
        btn_layout.addWidget(self.add_module_btn)

        self.download_guide_btn = QPushButton("下载模块说明")
        self.download_guide_btn.clicked.connect(self.download_guide)
        btn_layout.addWidget(self.download_guide_btn)

        layout.addLayout(btn_layout)

        # 漏洞模块勾选
        self.module_checks = []
        self.group_box = QGroupBox("选择漏洞模块")
        self.group_layout = QVBoxLayout()
        self.group_box.setLayout(self.group_layout)
        layout.addWidget(self.group_box)
        self.refresh_modules()

        # 开始按钮
        self.start_btn = QPushButton("开始检测")
        self.start_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.start_btn)

        # 日志显示
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background-color: black; color: white;")
        layout.addWidget(QLabel("日志输出:"))
        layout.addWidget(self.log_box)

        self.setLayout(layout)

    def refresh_modules(self):
        # 清空旧的勾选框
        for i in reversed(range(self.group_layout.count())):
            widget = self.group_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)
        self.module_checks.clear()
        # 重新加载模块
        load_modules(refresh=True)
        for module in ALL_MODULES:
            cb = QCheckBox(module.name)
            self.group_layout.addWidget(cb)
            self.module_checks.append(cb)

    def import_targets_from_txt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择目标TXT文件", "", "Text Files (*.txt)")
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            if lines:
                self.target_input.setText(";".join(lines))
                self.append_log(f"已导入 {len(lines)} 个目标。")
            else:
                self.append_log("TXT文件为空。")
        except Exception as e:
            QMessageBox.critical(self, "导入失败", f"导入目标失败: {e}")

    def start_scan(self):
        targets = self.target_input.text().strip()
        if not targets:
            self.append_log("请输入目标地址！")
            return
        targets = targets.split(";")
        # 去除空白和重复目标
        target_list = list(set([t.strip() for t in targets if t.strip()]))
        if not target_list:
            self.append_log("请输入有效的目标地址！")
            return
        # 检查是否选择了模块
        checked_modules = [module for cb, module in zip(self.module_checks, ALL_MODULES) if cb.isChecked()]
        if not checked_modules:
            self.append_log("请至少选择一个漏洞模块！")
            return
        # 清空日志
        self.log_box.clear()
        # 启动多线程扫描
        for target in target_list:
            task = ScanTask(target, checked_modules, self.log_signal)
            self.thread_pool.start(task)

    def append_log(self, text, color=None):
        if color:
            self.log_box.setTextColor(color)
        else:
            self.log_box.setTextColor(Qt.white)
        self.log_box.append(text)
        self.log_box.moveCursor(QTextCursor.End)
        self.log_box.setTextColor(Qt.white)

    def add_module(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择模块文件", "", "Python Files (*.py)")
        if not file_path:
            return
        try:
            base_name = os.path.basename(file_path)
            dest_path = os.path.join(MODULES_DIR, base_name)
            if os.path.exists(dest_path):
                reply = QMessageBox.question(self, "覆盖确认", f"{base_name} 已存在，是否覆盖？", QMessageBox.Yes | QMessageBox.No)
                if reply != QMessageBox.Yes:
                    return
            shutil.copy(file_path, dest_path)
            self.append_log(f"模块 {base_name} 添加成功，正在刷新模块列表...")
            self.refresh_modules()
        except Exception as e:
            QMessageBox.critical(self, "添加失败", f"添加模块失败: {e}")

    def download_guide(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "保存模块开发说明", "模块开发说明.md", "Markdown Files (*.md);;Text Files (*.txt)")
        if not file_path:
            return
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(MODULE_GUIDE)
            QMessageBox.information(self, "保存成功", "模块开发说明已保存。")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", f"保存说明失败: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = VulnGUI()
    gui.show()
    sys.exit(app.exec_())
