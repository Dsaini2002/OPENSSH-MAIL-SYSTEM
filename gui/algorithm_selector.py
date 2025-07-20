# gui/algorithm_selector.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QComboBox
)
from python_backend.quantum_algorithms import (
    get_supported_kex, get_supported_signatures, get_default_signature_name
)

class AlgorithmSelectorWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.kem_combo = QComboBox()
        self.sig_combo = QComboBox()

        self.init_ui()
        self.load_algorithms()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select Key Exchange (KEM):"))
        layout.addWidget(self.kem_combo)

        layout.addWidget(QLabel("Select Signature Algorithm:"))
        layout.addWidget(self.sig_combo)

        self.setLayout(layout)

    def load_algorithms(self):
        kems = get_supported_kex()
        sigs = get_supported_signatures()

        self.kem_combo.addItems(kems)

        for s in sigs:
            label = get_default_signature_name(s)
            self.sig_combo.addItem(label, s)

    def get_selected_kem(self):
        return self.kem_combo.currentText()

    def get_selected_signature(self):
        return self.sig_combo.currentData()  # this returns internal value like "mldsa87"
