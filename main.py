import sys
import sqlite3
import hashlib
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QVBoxLayout, QPushButton, \
    QMessageBox, QDialog, QHBoxLayout, QTableWidget, QTableWidgetItem, QVBoxLayout, QMainWindow

class DatabaseViewer(QMainWindow):
    def __init__(self, db_conn, username):
        super().__init__()

        self.setWindowTitle('Database Viewer')
        self.setGeometry(300, 300, 400, 200)

        self.db_conn = db_conn
        self.username = username

        self.table_widget = QTableWidget(self)
        self.populate_table()

        layout = QVBoxLayout()
        layout.addWidget(self.table_widget)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def populate_table(self):
        cursor = self.db_conn.cursor()
        cursor.execute('SELECT username, password FROM users')
        data = cursor.fetchall()

        self.table_widget.setRowCount(len(data))
        self.table_widget.setColumnCount(2)
        self.table_widget.setHorizontalHeaderLabels(['Username', 'Password'])

        for row_num, row_data in enumerate(data):
            for col_num, col_data in enumerate(row_data):
                item = QTableWidgetItem(str(col_data))
                self.table_widget.setItem(row_num, col_num, item)

class AddUserDialog(QDialog):
    def __init__(self, db_conn):
        super().__init__()

        self.setWindowTitle('Add User')
        self.setGeometry(300, 300, 300, 150)

        self.db_conn = db_conn

        self.label_username = QLabel('Username:')
        self.label_password = QLabel('Password:')

        self.edit_username = QLineEdit(self)
        self.edit_password = QLineEdit(self)
        self.edit_password.setEchoMode(QLineEdit.Password)

        self.btn_add_user = QPushButton('Add User', self)
        self.btn_add_user.clicked.connect(self.add_user)

        layout = QVBoxLayout()
        layout.addWidget(self.label_username)
        layout.addWidget(self.edit_username)
        layout.addWidget(self.label_password)
        layout.addWidget(self.edit_password)
        layout.addWidget(self.btn_add_user)

        self.setLayout(layout)

    def add_user(self):
        username = self.edit_username.text()
        password = self.edit_password.text()

        if not username or not password:
            QMessageBox.warning(self, 'Warning', 'Please enter both username and password.')
            return

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        cursor = self.db_conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        self.db_conn.commit()

        QMessageBox.information(self, 'Success', 'User added successfully.')

class LoginDialog(QDialog):
    def __init__(self, db_conn):
        super().__init__()

        self.setWindowTitle('Login')
        self.setGeometry(300, 300, 300, 150)

        self.db_conn = db_conn
        self.username = None  # Add a username attribute

        self.label_username = QLabel('Username:')
        self.label_password = QLabel('Password:')

        self.edit_username = QLineEdit(self)
        self.edit_password = QLineEdit(self)
        self.edit_password.setEchoMode(QLineEdit.Password)

        self.btn_login = QPushButton('Login', self)
        self.btn_login.clicked.connect(self.login)

        self.btn_add_user = QPushButton('Add User', self)
        self.btn_add_user.clicked.connect(self.show_add_user_dialog)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.btn_login)
        button_layout.addWidget(self.btn_add_user)

        layout = QVBoxLayout()
        layout.addWidget(self.label_username)
        layout.addWidget(self.edit_username)
        layout.addWidget(self.label_password)
        layout.addWidget(self.edit_password)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def login(self):
        username = self.edit_username.text()
        password = self.edit_password.text()

        if not username or not password:
            QMessageBox.warning(self, 'Login Failed', 'Please enter both username and password.')
            return

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        cursor = self.db_conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
        user = cursor.fetchone()

        if user:
            self.accept()
            self.username = username  # Set the username attribute
            self.show_database_viewer()
        else:
            QMessageBox.warning(self, 'Login Failed', 'Invalid username or password')

    def show_add_user_dialog(self):
        add_user_dialog = AddUserDialog(self.db_conn)
        add_user_dialog.exec_()

    def show_database_viewer(self):
        database_viewer = DatabaseViewer(self.db_conn, self.username)
        database_viewer.show()

    def get_username(self):
        return self.username

class PasswordManager(QWidget):
    def __init__(self, db_conn):
        super().__init__()

        self.db_conn = db_conn
        self.create_table()

        self.init_ui()

        # Show the login dialog on startup
        self.show_login_dialog()

    def create_table(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT
            )
        ''')
        self.db_conn.commit()

    def init_ui(self):
        self.setWindowTitle('Password Manager')
        self.setGeometry(300, 300, 400, 200)

        self.table_widget = QTableWidget(self)
        self.table_widget.setRowCount(0)
        self.table_widget.setColumnCount(2)
        self.table_widget.setHorizontalHeaderLabels(['Username', 'Password'])

        layout = QVBoxLayout()
        layout.addWidget(self.table_widget)

        self.setLayout(layout)

    def show_login_dialog(self):
        login_dialog = LoginDialog(self.db_conn)
        if login_dialog.exec_() == QDialog.Accepted:
            self.show_database_viewer(login_dialog.get_username())

    def show_database_viewer(self, username):
        database_viewer = DatabaseViewer(self.db_conn, username)
        database_viewer.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)

    try:
        # Connect to the SQLite3 database
        conn = sqlite3.connect('password_db.db')
    except sqlite3.Error as e:
        print(f"Error connecting to the database: {e}")
        sys.exit(1)

    try:
        window = PasswordManager(conn)
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error running the application: {e}")
        sys.exit(1)
