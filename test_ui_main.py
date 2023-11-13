from PyQt5 import QtCore, QtGui, QtWidgets



class MyMainWindow(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()


        self.accountCount = 0

        self.accounts = {
            'labels_account_name':{},
            'labels_username':{},
            'labels_password':{},
            'buttons_edit':{},
            'buttons_delete':{},
            'layouts':{},
        }

    def setupUi(self):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")

        self.pushButtonCreateNewAccount = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonCreateNewAccount.setText("Create New Account")
        self.pushButtonCreateNewAccount.setObjectName("pushButtonCreateNewAccount")
        self.verticalLayout.addWidget(self.pushButtonCreateNewAccount)

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
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 24))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    
        self.pushButtonCreateNewAccount.clicked.connect(self.openCreateNewAccountDialog)
    

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))

        
    
    def addButtonEdit(self):
        
        self.accounts['buttons_edit'][self.accountCount] = QtWidgets.QPushButton("Edit")
        self.accounts['buttons_edit'][self.accountCount].clicked.connect(self.openEditDialog)

    def addLabelUsername(self, username):

        self.accounts['labels_username'][self.accountCount] = QtWidgets.QLabel(f"Username:\t{username}")
    
    def addButtonDelete(self):

        self.accounts['buttons_delete'][self.accountCount] = QtWidgets.QPushButton("Delete")
        self.accounts['buttons_delete'][self.accountCount].clicked.connect(self.openDeleteDialog)
    
    def addLabelAccountName(self, account):
        
        self.accounts['labels_account_name'][self.accountCount] = QtWidgets.QLabel(account)

    def addLabelPassword(self, password):
        
        self.accounts['labels_password'][self.accountCount] = QtWidgets.QLabel(f"Password:\t{password}")
    
    def addLayout(self):

        self.accounts['layouts'][self.accountCount] = QtWidgets.QGridLayout()
        self.accounts['layouts'][self.accountCount].rowMinimumHeight(1500)
    
    def addAccount(self, account, username, password):

        self.addButtonEdit()
        self.addButtonDelete()
        self.addLabelAccountName(account)
        self.addLabelPassword(password)
        self.addLabelUsername(username)
        self.addLayout()
       
        self.accounts['layouts'][self.accountCount].addWidget(self.accounts['labels_account_name'][self.accountCount], 0, 0,2,1)
        self.accounts['layouts'][self.accountCount].addWidget(self.accounts['labels_password'][self.accountCount],1,1,1,2)
        self.accounts['layouts'][self.accountCount].addWidget(self.accounts['labels_username'][self.accountCount],0,1,1,2)
        self.accounts['layouts'][self.accountCount].addWidget(self.accounts['buttons_edit'][self.accountCount],0,3,1,1)
        self.accounts['layouts'][self.accountCount].addWidget(self.accounts['buttons_delete'][self.accountCount],1,3,1,1)

        # Adds it to the widget's layout so that it will scroll in the scroll area, if not it will not scroll
        self.widget.layout().addLayout(self.accounts['layouts'][self.accountCount])

        self.accountCount += 1

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
        
    def openDeleteDialog(self):
        
        sender = self.getSender(self)
        self.deleteDialog = QtWidgets.QDialog(MainWindow)
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

        sender = self.getSender(self)
        print(sender)

        index = list(self.accounts['buttons_edit'].keys())[list(self.accounts['buttons_edit'].values()).index(sender)]
        
        self.editDialog = QtWidgets.QDialog(MainWindow)
        self.editDialogui = Ui_Edit_Dialog()
        self.editDialogui.setupUi(self.editDialog)
        self.editDialog.setWindowModality(QtCore.Qt.ApplicationModal)

                                                                #                          This is only a temporary fix
                                                                #                          To make it permanent, make a 
                                                                #                          form layout and add the two seperately
        self.editDialogui.lineEditUsername.setText(f'{self.accounts['labels_username'][index].text()[10:]}')
        self.editDialogui.lineEditPassword.setText(f'{self.accounts['labels_password'][index].text()[10:]}')
        self.editDialogui.labelAccount.setText(f'{self.accounts['labels_account_name'][index].text()}')
        
        self.editDialog.rejected.connect(lambda: self.editDialog.close())
        self.editDialog.accepted.connect(lambda: self.updateAccount(index))

        self.editDialog.show()
    
    def openCreateNewAccountDialog(self):


        self.createNewAccountDialog = QtWidgets.QDialog(MainWindow)
        self.createNewAccountDialogui = Ui_Create_New_Account_Dialog()
        self.createNewAccountDialogui.setupUi(self.createNewAccountDialog)
        self.createNewAccountDialog.setWindowModality(QtCore.Qt.ApplicationModal)

        self.createNewAccountDialog.accepted.connect(lambda: self.addAccount(self.createNewAccountDialogui.lineEditAccount.text(), self.createNewAccountDialogui.lineEditUsername.text(), self.createNewAccountDialogui.lineEditPassword.text()))
        
        self.createNewAccountDialog.show()

    def updateAccount(self, index):

        self.updateItem('labels_username',index)
        self.updateItem('labels_password',index)
        

    def updateItem(self, type, index):

        match type:

            case 'labels_username':
                self.accounts[type][index].setText(f'Username:\t{self.editDialogui.lineEditUsername.text()}')
            
            case 'labels_password':
                self.accounts[type][index].setText(f'Password:\t{self.editDialogui.lineEditPassword.text()}')


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

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = MyMainWindow()
    MainWindow.setupUi()
    MainWindow.show()
    sys.exit(app.exec_())