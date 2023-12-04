from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
import sqlite3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sys, os

class MyMainWindow(QtWidgets.QMainWindow):

    def __init__(self):

        super().__init__()

        self.passwordsDecrypted = False
        self.onStartup = True
        self.setupUi()

        self.conn = sqlite3.connect('accounts.db')    

        self.accounts = {
            'labels_account_name':{},
            'labels_username':{},
            'labels_username_title':{},
            'labels_password':{},
            'labels_password_title':{},
            'buttons_edit':{},
            'buttons_delete':{},
            'layouts':{},
        }

        # Only runs self.createKeys() when the table for the public key doesn't exist
        #  - assumes the private key hasn't been created yet either
        cursor = self.conn.cursor()
        try:
            cursor.execute("SELECT * from public_key")
        except:
            self.createKeys()
        self.create_table()

        self.display_accounts = self.accounts

        self.load_accounts()

        self.private_key_file_path = None
        
        # WILL BE ABLE TO UPDATE SOON
        self.defaultOrganizeMode = "A -> Z"
        self.organizeAccounts(self.getOrganizeMode(), self.getDisplayIds(), self.lineEditSearchAccounts.text())
        self.onStartup = False
        try:
            self.current_dated_id = cursor.execute("SELECT dated_id FROM accounts").fetchall()[-1][0]
        except Exception:
            self.current_dated_id = 0


    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                account_name TEXT,
                username TEXT,
                password TEXT,
                dated_id INTEGER
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

    def add_account_to_db(self, id, account, username, password, dated_id):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO accounts VALUES (?, ?, ?, ?, ?)', (id, account, username, password, dated_id))
        self.conn.commit()

    def load_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM accounts')
        rows = cursor.fetchall()
        for row in rows:
            id, account_name, username, password = row[0], row[1], row[2], row[3]
            self.addAccount(self.accounts, id, account_name, username, password, 'loading')

    def setupUi(self):
        self.setObjectName("MainWindow")
        self.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")


        self.pushButtonCreateNewAccount = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonCreateNewAccount.setText("Create New Account")
        self.pushButtonCreateNewAccount.setObjectName("pushButtonCreateNewAccount")

        self.pushButtonHidePasswords = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonHidePasswords.setText("Hide Passwords")
        self.pushButtonHidePasswords.setObjectName("pushButtonHidePasswords")

        self.pushButtonShowPasswords = QtWidgets.QPushButton(self.centralwidget)
        self.pushButtonShowPasswords.setText("Show Passwords")
        self.pushButtonShowPasswords.setObjectName("pushButtonShowPasswords")

        self.seperatorLine = QtWidgets.QFrame(self.centralwidget)
        self.seperatorLine.setObjectName("seperatorLine")
        self.seperatorLine.setFrameShape(QtWidgets.QFrame.VLine)
        self.seperatorLine.setFrameShadow(QtWidgets.QFrame.Raised)

        self.lineEditSearchAccounts = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEditSearchAccounts.setObjectName("lineEditSearchAccounts")
        self.lineEditSearchAccounts.setPlaceholderText("Search")
        self.lineEditSearchAccounts.setMaximumSize(100,20)

        self.comboBoxAccountOrganizerModes = ["A -> Z", "Z -> A", "Newest -> Oldest", "Oldest -> Newest"]
        
        self.comboBoxAccountOrganizer = QtWidgets.QComboBox(self.centralwidget)
        self.comboBoxAccountOrganizer.addItems(self.comboBoxAccountOrganizerModes)
        self.comboBoxAccountOrganizer.setObjectName("comboBoxAccountOrganizer")
        self.comboBoxAccountOrganizer.setMaximumSize(120,20)
        

        self.scrollArea = QtWidgets.QScrollArea(self.centralwidget)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setMinimumSize(QtCore.QSize(0,275))


        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0,0,400,400))
        self.scrollAreaWidgetContents.setLayout(QtWidgets.QVBoxLayout())

        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        

        self.createAccountHideShowGridLayout = QtWidgets.QGridLayout()
        self.createAccountHideShowGridLayout.setObjectName("createAccountHideShowGridLayout")

        self.createAccountHideShowGridLayout.addWidget(self.pushButtonCreateNewAccount, 0, 0, 1, 2)
        self.createAccountHideShowGridLayout.addWidget(self.pushButtonHidePasswords, 1, 0, 1, 1 )
        self.createAccountHideShowGridLayout.addWidget(self.pushButtonShowPasswords, 1, 1, 1, 1)


        self.accountOrganizerGridLayout = QtWidgets.QGridLayout()
        self.accountOrganizerGridLayout.setObjectName("accountOrganizerGridLayout")

        self.accountOrganizerGridLayout.addWidget(self.lineEditSearchAccounts, 1, 0, 1, 1)
        self.accountOrganizerGridLayout.addWidget(self.comboBoxAccountOrganizer, 0, 0 ,1 ,1)


        self.mainGridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.mainGridLayout.setObjectName("mainGridLayout")

        self.mainGridLayout.addLayout(self.createAccountHideShowGridLayout, 0, 0, 2, 3)
        self.mainGridLayout.addWidget(self.seperatorLine, 0, 3, 2, 1)
        self.mainGridLayout.addLayout(self.accountOrganizerGridLayout, 0, 3, 2, 1)
        self.mainGridLayout.addWidget(self.scrollArea, 2, 0, 1, 4)


        self.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 24))
        self.menubar.setObjectName("menubar")
        self.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.setWindowIcon(QtGui.QIcon('232962.png'))
        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

        self.setDecryptEncryptButtonMode()

    
        self.pushButtonCreateNewAccount.clicked.connect(self.openCreateNewAccountDialog)
        self.pushButtonShowPasswords.clicked.connect(self.openDragAndDropForm)
        self.pushButtonHidePasswords.clicked.connect(self.hidePassowords)
        self.comboBoxAccountOrganizer.currentIndexChanged.connect(self.filterAccounts)
        self.lineEditSearchAccounts.returnPressed.connect(self.filterAccounts)
    

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Password Manager", "Password Manager"))

    def getOrganizeMode(self):
        return self.comboBoxAccountOrganizer.itemText(self.comboBoxAccountOrganizer.currentIndex())
    
    def getDisplayIds(self):

        displayIds = []
        for id in self.display_accounts['layouts']:
            displayIds.append(id)
        return displayIds
    
    def filterAccounts(self):
        try:
            self.labelHelpingSearch.deleteLater()
        except Exception:
            pass
        criteria = self.lineEditSearchAccounts.text()
        self.organizeAccounts(self.getOrganizeMode(), self.searchAccounts(criteria), criteria)   
    
    def searchAccounts(self, criteria):

        if criteria == '':
            return self.getDisplayIds()

        criteria = criteria.lower()

        cursor = self.conn.cursor()

        # finds account names that have the criteria in it
        matched_account_names = []
        for account_name in self.accounts['labels_account_name']:
            if criteria in self.accounts['labels_account_name'][account_name].text().lower():
                matched_account_names.append(self.accounts['labels_account_name'][account_name].text())
        # finds corresponding ids
        account_name_ids = []
        for account_name in matched_account_names:
            id = cursor.execute("SELECT id FROM accounts WHERE account_name = ?", (account_name,)).fetchall()
            if id not in account_name_ids:
                account_name_ids.append(id)
        # finds usernames that have the criteria in it
        matched_usernames = []
        for username in self.accounts['labels_username']:
            if criteria in self.accounts['labels_username'][username].text().lower():
                matched_usernames.append(self.accounts['labels_username'][username].text())
        # finds corresponding ids
        username_ids = []
        for username in matched_usernames:
            id = cursor.execute("SELECT id FROM accounts WHERE username = ?", (username,)).fetchall()
            if id not in username_ids:
                username_ids.append(id)
        
        if self.passwordsDecrypted:

            matched_password_labels = []
            for password in self.accounts['labels_password']:
                if criteria in self.accounts['labels_password'][password].text().lower():
                    matched_password_labels.append(self.accounts['labels_password'][password])
            password_ids = []

            for password_label in matched_password_labels:
                index = list(self.accounts['labels_password'].keys())[list(self.accounts['labels_password'].values()).index(password_label)]
                password_ids.append(index)

        

        # adds these three lists together and removes any duplicates
        data_base_ids = account_name_ids + username_ids
      
        all_ids = []
        for id_list in data_base_ids:
            for id in id_list:
                all_ids.append(id[0])
        try:
            all_ids = all_ids + password_ids
        except:
            pass
        unique_ids = []
        [unique_ids.append(x) for x in all_ids if x not in unique_ids]
        return unique_ids
             

    def organizeAccounts(self, mode, displayIds, criteria):
        

        # this hides all the accounts that aren't in the display ids and removes them from the scrollareawidgetcontents layout
        for id in self.accounts['layouts']: 
            if id in displayIds: # if the id is in the display ids, delete it since it will be added later in self.alphabetizeIds
                self.deleteAccount(self.display_accounts, id, 'organizing')
            if id not in displayIds: # if it isn't, remove the layout from the scrollareawidgetcontents layout and set the rest of the widgets
                                     # to not visible
                for category in self.accounts:
                    if category == 'layouts':
                        self.scrollAreaWidgetContents.layout().removeItem(self.accounts[category][id])
                    else:
                        self.accounts[category][id].setVisible(False)
        
        if mode == self.comboBoxAccountOrganizerModes[0]: # A to Z
            
            alphabetized_ids = self.alphabetizeIds(displayIds, 'A to Z', criteria)
            self.sortAccounts(alphabetized_ids)

        if mode == self.comboBoxAccountOrganizerModes[1]: # Z to A
            alphabetized_ids = self.alphabetizeIds(displayIds, 'Z to A', criteria)
            self.sortAccounts(alphabetized_ids)
        
        if mode == self.comboBoxAccountOrganizerModes[2]: # Newest to Oldest
            dated_ids = self.dateIds(displayIds, 'Newest to Oldest')
            self.sortAccounts(dated_ids)
        
        if mode == self.comboBoxAccountOrganizerModes[3]: #Oldest to Newest
            dated_ids = self.dateIds(displayIds, 'Oldest to Newest')
            self.sortAccounts(dated_ids)

    def dateIds(self, displayIds, direction):
        
        cursor = self.conn.cursor()
        # get all the dated_ids from the database, they're already sorted by the nature they're added to the database in
        dated_database_ids = []
        for id in displayIds:
            dated_database_ids.append(cursor.execute("SELECT dated_id FROM accounts WHERE id = ?", (id,)).fetchall())
        dated_ids = self.getIdsFromDatabaseIds(dated_database_ids)
        # gets the ids of the accounts that correspond with the database_ids
        # the ids of accounts will change sometimes, the database_ids will never change dynamically
        database_ids = []
        for id in dated_ids:
            database_ids.append(cursor.execute("SELECT id FROM accounts WHERE dated_id = ?", (id,)).fetchall())
        ids = self.getIdsFromDatabaseIds(database_ids)

        if direction == 'Newest to Oldest':
            ids.reverse()
            
        return ids

    def alphabetizeIds(self, displayIds, direction, criteria):

        account_name_list = []
        # gets a list of all the account names
        for id in displayIds:
            account_name_list.append(self.accounts['labels_account_name'][id].text())
        # alphabetizes them while ignoring uppercase vs lowercase      THIS PART
        alphabetized_account_name_list = sorted(account_name_list, key = str.casefold)
        if direction == 'Z to A':
            alphabetized_account_name_list.reverse()

        cursor = self.conn.cursor()
        # gets a list of UNIQUE ids that are in alphabetical order with respect to the id's corresponding account name
        alphabetical_database_ids = []
        for account_name in alphabetized_account_name_list:
            id = cursor.execute("SELECT id FROM accounts WHERE account_name = ?", (account_name,)).fetchall()
            if id not in alphabetical_database_ids:
                alphabetical_database_ids.append(id)
        # creates a list of just numbers, unlike lists which the SQLite database provides
        # just numbers can be worked with much easier
        # this has to be done on its own since some database ids have 1 item in the list while others have 2 or 3 or 4
        # so it cannot be done by appending above id[0][0]
        alphabetical_ids = self.getIdsFromDatabaseIds(alphabetical_database_ids)
        
        # this will check for any false positives
        # since multiple accounts can have the same account name, and that was what we are alphabetizing from,
        # sometimes an id can be falsely provided. ex:
        # account1: id = 1, account_name = amazon, username = shopper1969, password = password
        # account2: id = 2, account_name = amazon, username = iloveclothes, password = test
        # if I search for "shopper", then the first account will be hit, providing the id: 1
        # but since we sort the ids into "alphabetical" order based on their corresponding account_names,
        # we need to search for account_names from the database, which will then hit both account 1 and account 2
        # the same will happen if i search for "password" and the passwords are decrypted
        # we don't want this, so we check to see if the criteria is ACTUALLY in either the username or accountname or the password (if applicable)
        # if we don't find the criteria anywhere in the account information, we will remove that id from the list and then continue
        criteria = criteria.lower()
        if self.passwordsDecrypted:

            with open(self.private_key_file_path, 'rb') as privateKeyFile:
                private_key = serialization.load_pem_private_key(
                    privateKeyFile.read(),
                    password=None,
            )
            
            for id in alphabetical_ids:
                account_info = cursor.execute("SELECT account_name, username, password FROM accounts WHERE id = ?", (id,)).fetchall()
                if criteria not in account_info[0][0].lower() and criteria not in account_info[0][1].lower() and criteria not in self.decryptPassword(account_info[0][2], private_key).decode('ascii').lower():
                    alphabetical_ids.remove(id)
        
        else:
            for id in alphabetical_ids:
                account_info = cursor.execute("SELECT account_name, username, password FROM accounts WHERE id = ?", (id,)).fetchall()
                if criteria not in account_info[0][0].lower() and criteria not in account_info[0][1].lower():
                    alphabetical_ids.remove(id)
        
        return alphabetical_ids

    # when we get ids from the database when we use FETCHALL, not FETCHONE, we should run this method to get just the numbers
    def getIdsFromDatabaseIds(self, database_ids):
        ids = []
        for list in database_ids:
            for id in list:
                ids.append(id[0])
        return ids
        

    def sortAccounts(self, sorted_ids):

        cursor = self.conn.cursor()

        # adds the account back to the view, the 'organizing' argument for the nature parameter will keep it from
        # being added to the database for a second time
        for id in sorted_ids:
            info = cursor.execute("SELECT account_name, username, password FROM accounts WHERE id = ?", (id,)).fetchall()
            account_name = info[0][0]
            username = info[0][1]
            # if the private_key_file_path has been presented it will decrypt, if not it will set to '********'
            if self.private_key_file_path:
                password = self.accounts['labels_password'][id].text()
            else:
                password = '********'
            
            self.addAccount(self.display_accounts, id, account_name, username, password, 'organizing')
        
        if len(sorted_ids) == 0:
            self.labelHelpingSearch = QtWidgets.QLabel(self.centralwidget)
            self.labelHelpingSearch.setObjectName("labelHelpingSearch")
            if self.onStartup:
                self.labelHelpingSearch.setText("Create an account to get started!")
            else:
                self.labelHelpingSearch.setText("No results found...\nIf you are searching for a password you will\n need to show them first!")
                self.labelHelpingSearch.setStyleSheet("QLabel {color : red}")
            self.labelHelpingSearch.setMinimumSize(200,200)
            self.labelHelpingSearch.setWordWrap(True)
            self.labelHelpingSearch.setVisible(False)
            self.labelHelpingSearch.setAlignment(QtCore.Qt.AlignCenter)
            self.scrollAreaWidgetContents.layout().addWidget(self.labelHelpingSearch)
            self.labelHelpingSearch.setVisible(True)

    def setDecryptEncryptButtonMode(self):
        self.pushButtonShowPasswords.setEnabled(not self.passwordsDecrypted)
        self.pushButtonHidePasswords.setEnabled(self.passwordsDecrypted)

    def addButtonEdit(self, location, id):
        
        location['buttons_edit'][id] = QtWidgets.QPushButton("Edit")
        location['buttons_edit'][id].clicked.connect(self.openEditDialog)

    def addLabelUsername(self, location, id, username):

        location['labels_username'][id] = QtWidgets.QLabel(username)
    
    def addLabelUsernameTitle(self, location, id):

        location['labels_username_title'][id] = QtWidgets.QLabel("Username:")
    
    def addButtonDelete(self, location, id):

        location['buttons_delete'][id] = QtWidgets.QPushButton("Delete")
        location['buttons_delete'][id].clicked.connect(self.openDeleteDialog)
    
    def addLabelAccountName(self, location, id, account):
        
        location['labels_account_name'][id] = QtWidgets.QLabel(account)

    def addLabelPassword(self, location, id, password):

        if self.passwordsDecrypted:
            location['labels_password'][id] = QtWidgets.QLabel(password)
        else:
            location['labels_password'][id] = QtWidgets.QLabel("********")
    
    def addLabelPasswordTitle(self, location, id):
        
        location['labels_password_title'][id] = QtWidgets.QLabel("Password:")
    
    def addLayout(self, location, id):

        location['layouts'][id] = QtWidgets.QGridLayout()
        location['layouts'][id].rowMinimumHeight(3000)
    
    def addAccount(self, location, id, account, username, password, nature):

        self.addButtonEdit(location, id)
        self.addButtonDelete(location, id)
        self.addLabelAccountName(location, id, account)
        self.addLabelPassword(location, id, password)
        self.addLabelPasswordTitle(location, id)
        self.addLabelUsername(location, id, username)
        self.addLabelUsernameTitle(location, id)
        self.addLayout(location, id)
       
        location['layouts'][id].addWidget(location['labels_account_name'][id], 0, 0,2,1)
        location['layouts'][id].addWidget(location['labels_username_title'][id],0, 1, 1, 1)
        location['layouts'][id].addWidget(location['labels_password_title'][id], 1, 1, 1, 1)
        location['layouts'][id].addWidget(location['labels_password'][id],1,2,1,1)
        location['layouts'][id].addWidget(location['labels_username'][id],0,2,1,1)
        location['layouts'][id].addWidget(location['buttons_edit'][id],0,3,1,1)
        location['layouts'][id].addWidget(location['buttons_delete'][id],1,3,1,1)

        # Adds it to the widget's layout so that it will scroll in the scroll area, if not it will not scroll
        self.scrollAreaWidgetContents.layout().addLayout(location['layouts'][id])

        if nature == 'creating': 
            self.save_new_account()

        else:
            pass

    def deleteItem(self, location, type, index, nature):

        # Deletes the QLabel object from the screen AND deletes it from the dictionary if the nature is deleting and not, for example, organizing
        location[type][index].deleteLater()
        if nature == 'deleting':
            del location[type][index]               
                

    def deleteAccount(self, location, index, nature):

        self.deleteItem(location, 'labels_account_name', index, nature)
        self.deleteItem(location, 'labels_password', index, nature)
        self.deleteItem(location, 'labels_password_title', index, nature)
        self.deleteItem(location, 'labels_username',index, nature)
        self.deleteItem(location, 'labels_username_title', index, nature)
        self.deleteItem(location, 'buttons_edit', index, nature)
        self.deleteItem(location, 'buttons_delete', index, nature)
        self.deleteItem(location, 'layouts', index, nature)

    def deleteAccountFromDatabase(self, index):
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM accounts WHERE id = ?", (index,))
        self.conn.commit()
        
    def openDeleteDialog(self):

        if self.passwordsDecrypted == False:
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
        index = list(self.accounts['buttons_delete'].keys())[list(self.accounts['buttons_delete'].values()).index(sender)]
        self.deleteDialog.accepted.connect(lambda: self.deleteAccount(self.accounts, index, 'deleting'))
        # self.deleteDialog.accepted.connect(lambda: self.deleteAccount(self.display_accounts, index, 'deleting'))
        self.deleteDialog.accepted.connect(lambda: self.deleteAccountFromDatabase(index))
        self.deleteDialog.rejected.connect(lambda: self.deleteDialog.close())
        self.deleteDialog.show()

    def getSender(self, object):
        return object.sender()

    def openEditDialog(self):

        if self.passwordsDecrypted == False:
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
        self.editDialogui.lineEditUsername.setText(f'{self.accounts["labels_username"][id].text()}')
        self.editDialogui.lineEditPassword.setText(f'{self.accounts["labels_password"][id].text()}')
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

        self.createNewAccountDialog.accepted.connect(lambda: self.addAccount(self.accounts,
                                                                             id, 
                                                                            self.createNewAccountDialogui.lineEditAccount.text(),
                                                                            self.createNewAccountDialogui.lineEditUsername.text(),
                                                                            self.createNewAccountDialogui.lineEditPassword.text(),
                                                                            'creating'))
        self.createNewAccountDialog.accepted.connect(self.filterAccounts)
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
                return
            
            # Changes the binary variable we get from decryptPassword to a string that can be used in the setText() method
            plaintext = self.decryptPassword(password[0], private_key).decode('ascii')

            self.accounts['labels_password'][id].setText(plaintext)
        
        self.passwordsDecrypted = True
        self.setDecryptEncryptButtonMode()
            

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
        except Exception:
            return str(0)
        return plaintext

    def hidePassowords(self):

        for password in self.accounts['labels_password']:
            self.accounts['labels_password'][password].setText("********")

        self.private_key_file_path = None
        self.passwordsDecrypted = False
        self.setDecryptEncryptButtonMode()
        self.filterAccounts()
    
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
        dated_id = self.current_dated_id + 1
        self.current_dated_id += 1
        # Encrypt the password using RSA public key
        encrypted_password = self.encrypt_password(password)
        # Add the account to the SQLite database
        self.add_account_to_db(id, account_name, username, encrypted_password, dated_id)

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
                self.accounts[type][id].setText(self.editDialogui.lineEditUsername.text())
            
            case 'labels_password':
                if self.passwordsDecrypted:
                    self.accounts[type][id].setText(self.editDialogui.lineEditPassword.text())
                else:
                    self.accounts[type][id].setText('********')


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
        Dialog.setWindowTitle(_translate("Create Account", "Create Account"))
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
        Dialog.setWindowTitle(_translate("Warning", "Warning"))
        self.label.setText(_translate("Warning", "You are about to delete this account. Are you sure you want to continue? This action cannot be undone."))


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
        self.formLayout = QtWidgets.QFormLayout()
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
        Dialog.setWindowTitle(_translate("New Account", "New Account"))
        self.label.setText(_translate("Dialog", "Username:"))
        self.label_2.setText(_translate("Dialog", "Password:"))

class Ui_Drag_and_Drop_Dialog(QtWidgets.QDialog):

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

        self.setObjectName("Dialog")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.resize(450, 350)
        self.setMinimumSize(QtCore.QSize(450, 350))
        self.setAcceptDrops(True)
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setMinimumSize(QtCore.QSize(400, 250))
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

        self.fileDialogPushButton = QtWidgets.QPushButton("Or choose file")
        self.fileDialogPushButton.clicked.connect(self.openFileDialog)
        self.verticalLayout.addWidget(self.fileDialogPushButton)

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
                MainWindow.private_key_file_path = filepath
                MainWindow.decryptPasswords(filepath)
            else:
                
                self.label.setText("Error: Please only provide a .pem file please.")
                self.label.setStyleSheet("QLabel {color : red; border: 3px dashed #aaa}")
                return

        else:
            event.ignore()

    def openFileDialog(self):

        file_filter = 'Private key (*.pem)'
        filepath = QtWidgets.QFileDialog.getOpenFileName(
            parent = self,
            caption = 'Select your private_key.pem file',
            directory = os.getcwd(),
            filter = file_filter

        )

        self.close()
        MainWindow.private_key_file_path = filepath[0]
        MainWindow.decryptPasswords(filepath[0])

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Password Select", "Password Select"))
        self.label.setText(_translate("Password Select", "Drag and drop your private_key.pem file here to decrypt your passwords"))

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
        Dialog.setWindowTitle(_translate("Error", "Error"))
        self.label.setText(_translate("Error", "Error decrypting passwords. Are you sure you\'re using the right .pem file?"))

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
        Dialog.setWindowTitle(_translate("Decrypt Error", "Decrypt Error"))
        self.label.setText(_translate("Dialog", "To edit or delete an account you must decrypt the information first."))

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = MyMainWindow()
    MainWindow.show()
    sys.exit(app.exec_())
