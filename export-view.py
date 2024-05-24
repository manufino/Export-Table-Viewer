import sys
import pefile
import re
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QUrl
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QTreeView, QVBoxLayout, QWidget, QMenu, QAction, QStatusBar, QProgressBar, QMessageBox, QLabel, QStackedLayout, QCheckBox
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QClipboard

class ExportTableLoader(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            pe = pefile.PE(self.file_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
                export_data = []
                total_exports = len(exports)
                for i, exp in enumerate(exports):
                    if exp.name:
                        name = exp.name.decode('utf-8')
                    else:
                        name = f"Ordinal: {exp.ordinal}"
                    address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                    export_data.append((name, address))
                    self.progress.emit(int((i+1)/total_exports*100))
                self.result.emit(export_data)
            else:
                self.error.emit("No export table found")
        except pefile.PEFormatError as e:
            self.error.emit(str(e))

class NameCleaner(QThread):
    cleaned = pyqtSignal(list)

    def __init__(self, names):
        super().__init__()
        self.names = names

    def run(self):
        cleaned_names = [self.clean_symbol_name(name) for name in self.names]
        self.cleaned.emit(cleaned_names)

    def clean_symbol_name(self, name):
        # Improved regex to clean mangled names
        return re.sub(r'\?\?\w|@\w*|@@.*', '', name)

class ExportTableViewer(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Export Table Viewer")
        self.setGeometry(100, 100, 800, 600)

        self.tree_view = QTreeView()
        self.tree_model = QStandardItemModel()
        self.tree_model.setHorizontalHeaderLabels(["Name", "Address"])
        self.tree_view.setModel(self.tree_model)
        self.tree_view.setEditTriggers(QTreeView.NoEditTriggers)  # Make items non-editable
        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.open_context_menu)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #00ff00;
                width: 10px;
                margin: 1px;
            }
        """)

        self.statusBar().addPermanentWidget(self.progress_bar, 1)
        self.progress_bar.setVisible(False)

        self.empty_label = QLabel("Drag and drop a file here or open it from the menu", alignment=Qt.AlignCenter)
        self.empty_label.setStyleSheet("font-size: 16px; color: gray;")

        layout = QStackedLayout()
        layout.addWidget(self.tree_view)
        layout.addWidget(self.empty_label)
        layout.setCurrentIndex(1)  # Show the label initially

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QTreeView {
                border: 1px solid #000000;
                border-radius: 5px;
                font-size: 14px;  /* Increase font size */
            }
            QMenuBar {
                background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #e0e0e0, stop:1 #d0d0d0);
                border: none;
                padding: 5px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 5px;
            }
            QMenuBar::item:selected {
                background-color: #c0c0c0;
            }
            QStatusBar {
                background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #e0e0e0, stop:1 #d0d0d0);
                border: none;
            }
        """)

        self.original_names = []
        self.cleaned_names = []

        self.create_menu()
        self.setAcceptDrops(True)

    def create_menu(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('File')
        open_action = QAction('Open', self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = menubar.addMenu('Help')
        info_action = QAction('Information', self)
        info_action.triggered.connect(self.show_information)
        help_menu.addAction(info_action)

        # Checkbox
        self.clean_names_checkbox = QCheckBox("Clean Names", self)
        self.clean_names_checkbox.stateChanged.connect(self.toggle_clean_names)
        menubar.setCornerWidget(self.clean_names_checkbox, Qt.TopRightCorner)

    def open_file(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Executable Files (*.exe *.dll)")

        if file_dialog.exec_():
            file_path = file_dialog.selectedFiles()[0]
            self.empty_label.setText("Analyzing the file, please wait...")
            self.centralWidget().layout().setCurrentIndex(1)  # Show the label
            self.load_export_table(file_path)

    def load_export_table(self, file_path):
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.thread = ExportTableLoader(file_path)
        self.thread.progress.connect(self.update_progress)
        self.thread.result.connect(lambda data: self.display_export_table(data, file_path))
        self.thread.error.connect(self.display_error)
        self.thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def display_export_table(self, export_data, file_path):
        self.progress_bar.setVisible(False)
        self.tree_model.clear()
        self.tree_model.setHorizontalHeaderLabels(["Name", "Address"])
        self.original_names = []
        self.cleaned_names = []

        for name, address in export_data:
            name_item = QStandardItem(name)
            address_item = QStandardItem(address)
            name_item.setEditable(False)  # Make items non-editable
            address_item.setEditable(False)
            self.tree_model.appendRow([name_item, address_item])
            self.original_names.append(name)

        self.centralWidget().layout().setCurrentIndex(0)  # Show the tree view
        self.adjust_column_widths()
        self.statusBar().showMessage(f"Loaded: {file_path}")

        if self.clean_names_checkbox.isChecked():
            self.start_cleaning_names()

    def adjust_column_widths(self):
        total_width = self.tree_view.viewport().width()
        self.tree_view.setColumnWidth(0, int(total_width * 0.8))
        self.tree_view.setColumnWidth(1, int(total_width * 0.2))

    def display_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.tree_model.clear()
        self.tree_model.setHorizontalHeaderLabels(["Error"])
        self.tree_model.appendRow(QStandardItem(error_message))
        self.empty_label.setText("Drag and drop a file here or open it from the menu")
        self.centralWidget().layout().setCurrentIndex(1)  # Show the label
        self.statusBar().showMessage("Error loading file")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if len(urls) > 1:
            self.statusBar().showMessage("Please drag and drop only one file at a time.")
        elif urls:
            file_path = urls[0].toLocalFile()
            if file_path.endswith(('.exe', '.dll')):
                self.empty_label.setText("Analyzing the file, please wait...")
                self.centralWidget().layout().setCurrentIndex(1)  # Show the label
                self.load_export_table(file_path)

    def show_information(self):
        QMessageBox.information(self, "About Export Table Viewer", "Export Table Viewer\nVersion 1.0\nA tool to visualize the export table of DLL and executable files.")

    def open_context_menu(self, position):
        indexes = self.tree_view.selectedIndexes()
        if indexes:
            selected_index = indexes[0]
            name_index = self.tree_model.index(selected_index.row(), 0)
            address_index = self.tree_model.index(selected_index.row(), 1)
            name = self.tree_model.data(name_index)
            address = self.tree_model.data(address_index)

            context_menu = QMenu()
            copy_name_action = QAction("Copy Name", self)
            copy_address_action = QAction("Copy Address", self)
            copy_name_action.triggered.connect(lambda: self.copy_to_clipboard(name))
            copy_address_action.triggered.connect(lambda: self.copy_to_clipboard(address))

            context_menu.addAction(copy_name_action)
            context_menu.addAction(copy_address_action)
            context_menu.exec_(self.tree_view.viewport().mapToGlobal(position))

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def toggle_clean_names(self, state):
        if state == Qt.Checked:
            self.start_cleaning_names()
        else:
            self.restore_original_names()

    def start_cleaning_names(self):
        self.cleaner_thread = NameCleaner(self.original_names)
        self.cleaner_thread.cleaned.connect(self.apply_clean_names)
        self.cleaner_thread.start()

    def apply_clean_names(self, cleaned_names):
        self.cleaned_names = cleaned_names
        for row in range(self.tree_model.rowCount()):
            item = self.tree_model.item(row, 0)
            item.setText(self.cleaned_names[row])

    def restore_original_names(self):
        for row in range(self.tree_model.rowCount()):
            item = self.tree_model.item(row, 0)
            item.setText(self.original_names[row])

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ExportTableViewer()
    window.show()
    sys.exit(app.exec_())
