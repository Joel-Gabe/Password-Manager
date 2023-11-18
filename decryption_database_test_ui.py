from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
import sqlite3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sys

class MyMainWindow(QtWidgets.QMainWindow):

    def __init__(self):

        super().__init__()

        self.setupUi()

        self.conn = sqlite3.connect('accounts.db')    

        self.accounts = {
            'labels_account_name':{},
            'labels_username':{},
            'labels_password':{},
            'buttons_edit':{},
            'buttons_delete':{},
            'layouts':{},
        }

        self.showPasswords = False

        # Only runs self.createKeys() when the table for the public key doesn't exist
        #  - assumes the private key hasn't been created yet either
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * from public_key")
        except:
            self.createKeys()
        self.create_table()

        self.load_accounts()


    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                account_name TEXT,
                username TEXT,
                password TEXT
            )
        ''')
        self.conn.commit()

    def createKeys(self):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
                )
        
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Writes the private key to its own file in writing bytes mode - very important!
        # Ideal case is that user will remove this file from the computer 
        # and store it on a thumbdrive or something
        with open("private_key.pem", 'wb') as privateKeyFile:

            privateKeyFile.write(private_key_bytes)
            
        cursor = self.conn.cursor()
        # Adds the public key into the database since the security of it does not matter
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS public_key (
                public_key BLOB
            )
        ''')
        cursor.execute('INSERT INTO public_key VALUES (?)', (public_key_bytes,))

        self.conn.commit()

    def add_account_to_db(self, id, account, username, password):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO accounts VALUES (?, ?, ?, ?)', (id, account, username, password))
        self.conn.commit()

    def load_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM accounts')
        rows = cursor.fetchall()
        for row in rows:
            id, account_name, username, password = row[0], row[1], row[2], row[3]
            self.addAccount(id, account_name, username, password, 'loading')

    def setupUi(self):
        self.setObjectName("MainWindow")
        self.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")

        self.pushButtonCreateNewAccount = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonCreateNewAccount.setText("Create New Account")
        self.pushButtonCreateNewAccount.setObjectName("pushButtonCreateNewAccount")
        self.verticalLayout.addWidget(self.pushButtonCreateNewAccount)

        self.pushButtonDecryptPasswords = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonDecryptPasswords.setText("Decrypt Passwords")
        self.pushButtonDecryptPasswords.setObjectName("pushButtonDecryptPasswords")
        self.verticalLayout.addWidget(self.pushButtonDecryptPasswords)

        self.verticalLayout_2.addLayout(self.verticalLayout)

        self.widget = QtWidgets.QWidget()
        self.widget.setGeometry(QtCore.QRect(0,0,500,500))
        self.widget.setLayout(QtWidgets.QVBoxLayout())


        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollArea.setWidget(self.widget)

        self.scrollArea.setWidget(self.widget)
        self.verticalLayout_2.addWidget(self.scrollArea)
        self.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 24))
        self.menubar.setObjectName("menubar")
        self.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    
        self.pushButtonCreateNewAccount.clicked.connect(self.openCreateNewAccountDialog)
        self.pushButtonDecryptPasswords.clicked.connect(self.openDragAndDropForm)
    

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("MainWindow", "MainWindow"))
  
    
    def addButtonEdit(self, id):
        
        self.accounts['buttons_edit'][id] = QtWidgets.QPushButton("Edit")
        self.accounts['buttons_edit'][id].clicked.connect(self.openEditDialog)

    def addLabelUsername(self, id, username):

        self.accounts['labels_username'][id] = QtWidgets.QLabel(f"Username:\t{username}")
    
    def addButtonDelete(self, id):

        self.accounts['buttons_delete'][id] = QtWidgets.QPushButton("Delete")
        self.accounts['buttons_delete'][id].clicked.connect(self.openDeleteDialog)
    
    def addLabelAccountName(self, id, account):
        
        self.accounts['labels_account_name'][id] = QtWidgets.QLabel(account)

    def addLabelPassword(self, id, password):

        if self.showPasswords:
            self.accounts['labels_password'][id] = QtWidgets.QLabel(f"Password:\t{password}")
        else:
            self.accounts['labels_password'][id] = QtWidgets.QLabel(f"Password:\t********")
    
    def addLayout(self, id):

        self.accounts['layouts'][id] = QtWidgets.QGridLayout()
        self.accounts['layouts'][id].rowMinimumHeight(1500)
    
    def addAccount(self, id, account, username, password, nature):

        

        self.addButtonEdit(id)
        self.addButtonDelete(id)
        self.addLabelAccountName(id, account)
        self.addLabelPassword(id, password)
        self.addLabelUsername(id, username)
        self.addLayout(id)
       
        self.accounts['layouts'][id].addWidget(self.accounts['labels_account_name'][id], 0, 0,2,1)
        self.accounts['layouts'][id].addWidget(self.accounts['labels_password'][id],1,1,1,2)
        self.accounts['layouts'][id].addWidget(self.accounts['labels_username'][id],0,1,1,2)
        self.accounts['layouts'][id].addWidget(self.accounts['buttons_edit'][id],0,3,1,1)
        self.accounts['layouts'][id].addWidget(self.accounts['buttons_delete'][id],1,3,1,1)

        # Adds it to the widget's layout so that it will scroll in the scroll area, if not it will not scroll
        self.widget.layout().addLayout(self.accounts['layouts'][id])

        if nature == 'creating': 
            self.save_new_account()

        else:
            pass

    def deleteItem(self, type, index):

        # Deletes the QLabel object from the screen AND deletes it from the dictionary
        self.accounts[type][index].deleteLater()
        del self.accounts[type][index]               
                

    def deleteAccount(self, index):

        self.deleteItem('labels_account_name', index)
        self.deleteItem('labels_password', index)
        self.deleteItem('labels_username',index)
        self.deleteItem('buttons_edit', index)
        self.deleteItem('buttons_delete', index)
        self.deleteItem('layouts', index)

        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM accounts WHERE id = ?", (index,))
        self.conn.commit()
        
    def openDeleteDialog(self):

        if self.showPasswords == False:
            self.openDecryptFirstDialog()
            return
        
        sender = self.getSender(self)
        self.deleteDialog = QtWidgets.QDialog(self)
        self.deleteDialogui = Ui_Delete_Dialog()
        self.deleteDialogui.setupUi(self.deleteDialog)
        self.deleteDialog.setWindowModality(QtCore.Qt.ApplicationModal)
        # The abomination in the argument here is a way to find the key based off of the value in a dictionary
        # Python has a way to find the value based off the key, but not the other way around, so this is what works
        # Since two objects will never be created so that they have the same object name, this will work. 
        # If there are two objects that have the same name, it won't, we don't have that problem however
        # list(self.accounts['buttons_delete'].keys())[list(self.accounts['buttons_delete'].values()).index(sender)]
        self.deleteDialog.accepted.connect(lambda: self.deleteAccount(list(self.accounts['buttons_delete'].keys())[list(self.accounts['buttons_delete'].values()).index(sender)]))
        self.deleteDialog.rejected.connect(lambda: self.deleteDialog.close())
        self.deleteDialog.show()

    def getSender(self, object):
        return object.sender()

    def openEditDialog(self):

        if self.showPasswords == False:
            self.openDecryptFirstDialog()
            return

        sender = self.getSender(self)

        id = list(self.accounts['buttons_edit'].keys())[list(self.accounts['buttons_edit'].values()).index(sender)]
        
        self.editDialog = QtWidgets.QDialog(self)
        self.editDialogui = Ui_Edit_Dialog()
        self.editDialogui.setupUi(self.editDialog)
        self.editDialog.setWindowModality(QtCore.Qt.ApplicationModal)

                                                                #                          This is only a temporary fix
                                                                #                          To make it permanent, make a 
                                                                #                          form layout and add the two seperately
        self.editDialogui.lineEditUsername.setText(f'{self.accounts["labels_username"][id].text()[10:]}')
        self.editDialogui.lineEditPassword.setText(f'{self.accounts["labels_password"][id].text()[10:]}')
        self.editDialogui.labelAccount.setText(f'{self.accounts["labels_account_name"][id].text()}')
        
        self.editDialog.rejected.connect(lambda: self.editDialog.close())
        self.editDialog.accepted.connect(lambda: self.updateAccount(id))

        self.editDialog.show()
    
    def openCreateNewAccountDialog(self):


        self.createNewAccountDialog = QtWidgets.QDialog(self)
        self.createNewAccountDialogui = Ui_Create_New_Account_Dialog()
        self.createNewAccountDialogui.setupUi(self.createNewAccountDialog)
        self.createNewAccountDialog.setWindowModality(QtCore.Qt.ApplicationModal)

        # Since it's creating a new account, have to add 1 to make it a new id
        id = self.getNextId()

        self.createNewAccountDialog.accepted.connect(lambda: self.addAccount(id, 
                                                                            self.createNewAccountDialogui.lineEditAccount.text(),
                                                                            self.createNewAccountDialogui.lineEditUsername.text(),
                                                                            self.createNewAccountDialogui.lineEditPassword.text(),
                                                                            'creating'))
        self.createNewAccountDialog.show()

    def openDecryptFirstDialog(self):
        self.decryptFirstDialog = Ui_Decrypt_First_Dialog(self)
        self.decryptFirstDialog.show()
    
    def openDragAndDropForm(self):

        self.dragAndDropDialog = Ui_Drag_and_Drop_Dialog(self)
        self.dragAndDropDialog.show()

    def getSerializedPublicKey(self):

        cursor = self.conn.cursor()
        public_key_data = cursor.execute("SELECT public_key FROM public_key").fetchall()
        self.conn.commit()
        # Since we are accessing the public key from the SQLite database, these indexes are required to reach the 
        # wanted data (the true serialized public key)
        return public_key_data[0][0]
    
    def encrypt_password(self, password):

        serialized_public_key = self.getSerializedPublicKey()
        # Load the serialized public key
        
        public_key = serialization.load_pem_public_key(serialized_public_key)

        # Encrypt the password using RSA public key
        ciphertext = public_key.encrypt(
            password.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext
    
    def decryptPasswords(self, filename):

        self.showPasswords = True
        cursor = self.conn.cursor()
        ciphertexts = cursor.execute("SELECT password FROM accounts").fetchall()

        with open(filename, 'rb') as privateKeyFile:
            private_key = serialization.load_pem_private_key(
                privateKeyFile.read(),
                password=None,
        )

        for password in ciphertexts:
            id = cursor.execute("SELECT id FROM accounts WHERE password = ?", (password)).fetchone()[0]

            # This checks to see if the right .pem file was submitted
            # The drag and drop checks to see if it IS a .pem file, but it can't be sure that it's the right one
            # This allows it to make sure it's the right one
            # Since the output from self.decryptPassword will NEVER be a string, unless the except is caught,
            # this will never produce a false positive
            plaintext = self.decryptPassword(password[0], private_key)
            if plaintext == '0':
                self.wrong_Pem_Error = Ui_Wrong_Pem_Error_Dialog(self)
                self.wrong_Pem_Error.show()
                break


            plaintext = str(self.decryptPassword(password[0], private_key)).strip("b'").rstrip("'")

            self.accounts['labels_password'][id].setText(f'Password:\t{plaintext}')
            

    def decryptPassword(self, ciphertext, private_key):

        # This will get caught when the wrong .pem file is provided since the 
        # private_key.decrypt() will throw an error
        # The zero in the string is arbitary, as long as a data type other than binary is returned
        # this will work, I just chose a string and a 0
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            #print("Error decrypting passwords. Are you sure you're using the right '.pem' file?")
            return str(0)
        return plaintext


    
    def getCurrentId(self):

        cursor = self.conn.cursor()
        try:
            id = cursor.execute("SELECT id FROM accounts").fetchall()[-1][0]
        except Exception:
            return 0
        self.conn.commit()
        return id
    
    def getNextId(self):
        return self.getCurrentId() + 1

    def save_new_account(self):
        account_name = self.createNewAccountDialogui.lineEditAccount.text()
        username = self.createNewAccountDialogui.lineEditUsername.text()
        password = self.createNewAccountDialogui.lineEditPassword.text()
        id = self.getNextId()
        # Encrypt the password using RSA public key
        encrypted_password = self.encrypt_password(password)
        # Add the account to the SQLite database
        self.add_account_to_db(id, account_name, username, encrypted_password)

    def updateAccount(self, id):

        self.updateItem('labels_username',id)
        self.updateItem('labels_password',id)

        cursor = self.conn.cursor()

        cursor.execute("UPDATE accounts SET username = ? WHERE id = ?", (self.editDialogui.lineEditUsername.text(), id))

        
        updated_password = self.encrypt_password(self.editDialogui.lineEditPassword.text())

        cursor.execute("UPDATE accounts SET password = ? WHERE id = ?", (updated_password, id))

        self.conn.commit()
        

    def updateItem(self, type, id):

        match type:

            case 'labels_username':
                self.accounts[type][id].setText(f'Username:\t{self.editDialogui.lineEditUsername.text()}')
            
            case 'labels_password':
                if self.showPasswords:
                    self.accounts[type][id].setText(f'Password:\t{self.editDialogui.lineEditPassword.text()}')
                else:
                    self.accounts[type][id].setText(f'Password:\t********')


class Ui_Create_New_Account_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 300)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("Cochin")
        font.setPointSize(22)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setObjectName("formLayout")
        self.labelAccount = QtWidgets.QLabel(Dialog)
        self.labelAccount.setObjectName("labelAccount")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.labelAccount)
        self.lineEditAccount = QtWidgets.QLineEdit(Dialog)
        self.lineEditAccount.setMinimumSize(QtCore.QSize(225, 0))
        self.lineEditAccount.setObjectName("lineEditAccount")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.lineEditAccount)
        self.labelUsername = QtWidgets.QLabel(Dialog)
        self.labelUsername.setObjectName("labelUsername")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.labelUsername)
        self.lineEditUsername = QtWidgets.QLineEdit(Dialog)
        self.lineEditUsername.setMinimumSize(QtCore.QSize(225, 0))
        self.lineEditUsername.setObjectName("lineEditUsername")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.lineEditUsername)
        self.labelPassword = QtWidgets.QLabel(Dialog)
        self.labelPassword.setObjectName("labelPassword")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.labelPassword)
        self.lineEditPassword = QtWidgets.QLineEdit(Dialog)
        self.lineEditPassword.setMinimumSize(QtCore.QSize(225, 0))
        self.lineEditPassword.setObjectName("lineEditPassword")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.lineEditPassword)
        self.gridLayout.addLayout(self.formLayout, 1, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 2, 0, 1, 1)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Create New Account"))
        self.labelAccount.setText(_translate("Dialog", "Account:"))
        self.labelUsername.setText(_translate("Dialog", "Username:"))
        self.labelPassword.setText(_translate("Dialog", "Password:"))


class Ui_Delete_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 300)
        Dialog.setSizeGripEnabled(False)
        Dialog.setModal(False)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(30, 240, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Yes)
        self.buttonBox.setCenterButtons(False)
        self.buttonBox.setObjectName("buttonBox")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(60, 40, 291, 151))
        font = QtGui.QFont()
        font.setPointSize(20)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.label.setMinimumWidth(291)
        self.label.setMinimumHeight(151)

        self.gridLayout.addWidget(self.label,0,0,1,1)
        self.gridLayout.addWidget(self.buttonBox,1,0,1,1)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "You are about to delete this account. Are you sure you want to continue? This action cannot be undone."))


class Ui_Edit_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(400, 300)
        Dialog.setSizeGripEnabled(False)
        Dialog.setModal(False)

        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")

        
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setGeometry(QtCore.QRect(30, 240, 341, 32))
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.formLayout = QtWidgets.QFormLayout(Dialog)
        self.formLayout.setLabelAlignment(QtCore.Qt.AlignCenter)
        self.formLayout.setFormAlignment(QtCore.Qt.AlignCenter)
        self.formLayout.setContentsMargins(0, 0, 0, 0)
        self.formLayout.setObjectName("formLayout")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setMinimumSize(QtCore.QSize(0, 0))
        self.label.setObjectName("label")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.label)
        self.lineEditUsername = QtWidgets.QLineEdit(Dialog)
        self.lineEditUsername.setMinimumSize(QtCore.QSize(0, 0))
        self.lineEditUsername.setObjectName("lineEdit")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.lineEditUsername)
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole, self.label_2)
        self.lineEditPassword = QtWidgets.QLineEdit(Dialog)
        self.lineEditPassword.setObjectName("lineEdit_2")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole, self.lineEditPassword)

        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setObjectName("label_3")
        self.label_3.setText("Account:")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.label_3)

        self.labelAccount = QtWidgets.QLabel(Dialog)
        self.labelAccount.setObjectName("labelAccount")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.labelAccount)

        self.lineEditUsername.setMinimumWidth(225)
        self.lineEditPassword.setMinimumWidth(225)

        self.lineEditUsername.setPlaceholderText("Enter Username")
        self.lineEditPassword.setPlaceholderText("Enter Password")

        self.gridLayout.addLayout(self.formLayout,0,0,1,1)
        self.gridLayout.addWidget(self.buttonBox,1,0,1,1)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept) # type: ignore
        self.buttonBox.rejected.connect(Dialog.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Username:"))
        self.label_2.setText(_translate("Dialog", "Password:"))

class Ui_Drag_and_Drop_Dialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

        self.setObjectName("Dialog")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(450, 350)
        self.setMinimumSize(QtCore.QSize(400, 300))
        self.setAcceptDrops(True)
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setMinimumSize(QtCore.QSize(400, 300))
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.label.setStyleSheet('''
            QLabel{
                border: 3px dashed #aaa
            }
        ''')
        self.label.setAcceptDrops(True)
        self.verticalLayout.addWidget(self.label)

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()
    
    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()

            # Returns filepath local to the computer
            filepath = str(event.mimeData().urls()[0].toLocalFile())
            # Finds the '.pem' ending
            filepath_ending = filepath[-4:-1] + filepath[-1]
            
            if filepath_ending == '.pem':
                self.close()
                MainWindow.decryptPasswords(filepath)
            else:
                
                self.label.setText("Error: Please only provide a .pem file please.")
                self.label.setStyleSheet("QLabel {color : red; border: 3px dashed #aaa}")
                return

        else:
            event.ignore()

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Drag and drop your private_key.pem file here"))

class Ui_Wrong_Pem_Error_Dialog(QtWidgets.QDialog):
    
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("Dialog")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(300, 225)
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setTextFormat(QtCore.Qt.AutoText)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Close)
        self.buttonBox.setCenterButtons(False)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(self)
        self.buttonBox.accepted.connect(self.accept) # type: ignore
        self.buttonBox.rejected.connect(self.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(self)
        

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "Error decrypting passwords. Are you sure you\'re using the right .pem file?"))

class Ui_Decrypt_First_Dialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setObjectName("Dialog")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(307, 217)
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)

        self.retranslateUi(self)
        self.buttonBox.accepted.connect(self.accept) # type: ignore
        self.buttonBox.rejected.connect(self.reject) # type: ignore
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", "To edit or delete an account you must decrypt the information first."))

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = MyMainWindow()
    MainWindow.show()
    sys.exit(app.exec_())
