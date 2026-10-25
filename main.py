import sys
import whois
from PySide6.QtWidgets import QApplication
from gui import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("BLADE OSINT")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
