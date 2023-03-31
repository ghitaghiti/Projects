from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QPushButton, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
import hashlib
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.NonModal)
        MainWindow.setEnabled(True)
        MainWindow.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        MainWindow.setFixedSize(990, 540)
        MainWindow.setWindowIcon(QIcon('./imgs/st.png'))
        MainWindow.setWindowOpacity(1.0)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        icon_open=r"./chaa_icons/open.png"
        icon_save=r"./chaa_icons/save.png"
        icon_exit=r"./chaa_icons/exit.png"
        icon_aes=r"./chaa_icons/aes.png"
        icon_rsa=r"./chaa_icons/rsa.png"
        icon_help=r"./chaa_icons/help.png"
        icon_about=r"./chaa_icons/info.png"
        icon_calculate=r"./chaa_icons/ok.png"

        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(0, 10, 990, 85))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.lbl_title = QtWidgets.QLabel(self.verticalLayoutWidget)
        
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(36)
        font.setBold(True)
        font.setItalic(False)
        font.setWeight(75)
        font.setKerning(True)
        
        self.lbl_title.setFont(font)
        self.lbl_title.setStyleSheet("color: rgb(1, 42, 95)")
        self.lbl_title.setScaledContents(False)
        self.lbl_title.setAlignment(QtCore.Qt.AlignCenter)
        self.lbl_title.setObjectName("lbl_title")
        self.verticalLayout.addWidget(self.lbl_title)
        self.lbl_sub_title = QtWidgets.QLabel(self.verticalLayoutWidget)
        
        font = QtGui.QFont()
        font.setPointSize(14)
        
        self.lbl_sub_title.setFont(font)
        self.lbl_sub_title.setStyleSheet("color: rgb(1, 42, 95)")
        self.lbl_sub_title.setAlignment(QtCore.Qt.AlignCenter)
        self.lbl_sub_title.setObjectName("lbl_sub_title")
        self.verticalLayout.addWidget(self.lbl_sub_title)
        
        self.verticalLayoutWidget_3 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_3.setGeometry(QtCore.QRect(10, 170, 71, 251))
        self.verticalLayoutWidget_3.setObjectName("verticalLayoutWidget_3")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_3)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        
        self.chk_md5 = QtWidgets.QCheckBox(self.verticalLayoutWidget_3)
        self.chk_md5.setObjectName("chk_md5")
        self.verticalLayout_3.addWidget(self.chk_md5)
        self.chk_sha1 = QtWidgets.QCheckBox(self.verticalLayoutWidget_3)
        self.chk_sha1.setObjectName("chk_sha1")
        self.verticalLayout_3.addWidget(self.chk_sha1)
        self.chk_sha256 = QtWidgets.QCheckBox(self.verticalLayoutWidget_3)
        self.chk_sha256.setObjectName("chk_sha256")
        self.verticalLayout_3.addWidget(self.chk_sha256)
        self.chk_sha384 = QtWidgets.QCheckBox(self.verticalLayoutWidget_3)
        self.chk_sha384.setObjectName("chk_sha384")
        self.verticalLayout_3.addWidget(self.chk_sha384)
        self.chk_sha512 = QtWidgets.QCheckBox(self.verticalLayoutWidget_3)
        self.chk_sha512.setObjectName("chk_sha512")
        self.verticalLayout_3.addWidget(self.chk_sha512)
        
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(80, 180, 790, 231))
        self.verticalLayoutWidget_4.setObjectName("verticalLayoutWidget_4")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_4)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
       
        self.lbl_md5 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.lbl_md5.setFrameShape(QtWidgets.QFrame.Box)
        self.lbl_md5.setText("")
        self.lbl_md5.setObjectName("lbl_md5")
        self.verticalLayout_4.addWidget(self.lbl_md5)
        self.lbl_sha1 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.lbl_sha1.setFrameShape(QtWidgets.QFrame.Box)
        self.lbl_sha1.setText("")
        self.lbl_sha1.setObjectName("lbl_sha1")
        self.verticalLayout_4.addWidget(self.lbl_sha1)
        self.lbl_256 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.lbl_256.setFrameShape(QtWidgets.QFrame.Box)
        self.lbl_256.setText("")
        self.lbl_256.setObjectName("lbl_256")
        self.verticalLayout_4.addWidget(self.lbl_256)
        self.lbl_386 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.lbl_386.setFrameShape(QtWidgets.QFrame.Box)
        self.lbl_386.setText("")
        self.lbl_386.setObjectName("lbl_386")
        self.verticalLayout_4.addWidget(self.lbl_386)
        self.lbl_512 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.lbl_512.setFrameShape(QtWidgets.QFrame.Box)
        self.lbl_512.setText("")
        self.lbl_512.setObjectName("lbl_512")
        self.verticalLayout_4.addWidget(self.lbl_512)
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(10, 104, 975, 61))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
       
        self.lbl_file = QtWidgets.QLabel(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lbl_file.sizePolicy().hasHeightForWidth())
        self.lbl_file.setSizePolicy(sizePolicy)
        self.lbl_file.setSizeIncrement(QtCore.QSize(0, 2))
        self.lbl_file.setBaseSize(QtCore.QSize(0, 0))
        self.lbl_file.setScaledContents(False)
        self.lbl_file.setOpenExternalLinks(False)
        self.lbl_file.setObjectName("lbl_file")
        self.horizontalLayout.addWidget(self.lbl_file)
        
        self.file_path = QtWidgets.QTextEdit(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.file_path.sizePolicy().hasHeightForWidth())
        self.file_path.setSizePolicy(sizePolicy)
        self.file_path.setObjectName("file_path")
        self.horizontalLayout.addWidget(self.file_path)
        self.btn_open = QPushButton(self.horizontalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.btn_open.sizePolicy().hasHeightForWidth())
        
        self.btn_open.setSizePolicy(sizePolicy)
        self.btn_open.setMaximumSize(QtCore.QSize(16777204, 16777215))
        self.btn_open.setObjectName("btn_open")
        self.btn_open.clicked.connect(self.display_message)

        self.horizontalLayout.addWidget(self.btn_open)
        
        self.verticalLayoutWidget_5 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_5.setGeometry(QtCore.QRect(900, 210, 77, 80))
        self.verticalLayoutWidget_5.setObjectName("verticalLayoutWidget_5")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_5)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        
        self.btn_aes = QPushButton(self.verticalLayoutWidget_5)
        self.btn_aes.setObjectName("btn_aes")
        self.verticalLayout_5.addWidget(self.btn_aes)
        self.btn_aes.clicked.connect(self.aes_crypt)

        self.btn_rsa = QPushButton(self.verticalLayoutWidget_5)
        self.btn_rsa.setObjectName("btn_rsa")
        self.verticalLayout_5.addWidget(self.btn_rsa)
        self.btn_rsa.clicked.connect(self.rsa_crypt)

        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(0, 160, 990, 20))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setGeometry(QtCore.QRect(0, 90, 990, 20))
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.verticalLayoutWidget_6 = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget_6.setGeometry(QtCore.QRect(900, 180, 90, 31))
        self.verticalLayoutWidget_6.setObjectName("verticalLayoutWidget_6")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_6)
        self.verticalLayout_6.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.lbl_saveas = QtWidgets.QLabel(self.verticalLayoutWidget_6)
        self.lbl_saveas.setObjectName("lbl_saveas")
        self.verticalLayout_6.addWidget(self.lbl_saveas)
        self.lbl_supmti = QtWidgets.QLabel(self.centralwidget)
        self.lbl_supmti.setGeometry(QtCore.QRect(10, 440, 801, 31))
        font = QtGui.QFont()
        font.setFamily("Lato Black")
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.lbl_supmti.setFont(font)
        self.lbl_supmti.setStyleSheet("color: Red")
        self.lbl_supmti.setObjectName("lbl_supmti")
       
        self.btn_calculate = QPushButton(self.centralwidget)
        self.btn_calculate.setGeometry(QtCore.QRect(380, 420, 120,26))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.btn_calculate.setFont(font)
        self.btn_calculate.setIcon(QIcon(icon_calculate))
        self.btn_calculate.setIconSize(QtCore.QSize(16, 16))
        self.btn_calculate.setObjectName("btn_calculate")
        self.btn_calculate.clicked.connect(self.hash_calculate)
       
        self.btn_exit = QPushButton(self.centralwidget)
        self.btn_exit.setGeometry(QtCore.QRect(520, 420, 120,26))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.btn_exit.setFont(font)
        self.btn_exit.setIcon(QIcon(icon_exit))
        self.btn_exit.setIconSize(QtCore.QSize(16, 16))
        self.btn_exit.setObjectName("btn_exit")
        self.btn_exit.clicked.connect(MainWindow.close)   

        self.lbl_names = QtWidgets.QLabel(self.centralwidget)
        self.lbl_names.setGeometry(QtCore.QRect(10, 470, 101, 21))
        self.lbl_names.setStyleSheet("color: Blue")
        self.lbl_names.setObjectName("lbl_names")
        MainWindow.setCentralWidget(self.centralwidget)
        
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuAlgorithms = QtWidgets.QMenu(self.menubar)
        self.menuAlgorithms.setObjectName("menuAlgorithms")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        self.menuHash = QtWidgets.QMenu(self.menubar)
        self.menuHash.setObjectName("menuHash")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        
        self.mn_open = QtWidgets.QAction(MainWindow)
        self.mn_open.setIcon(QIcon(icon_open))
        self.mn_open.setObjectName("mn_open")

        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")
        self.mn_exit = QtWidgets.QAction(MainWindow)
        self.mn_exit.setObjectName("mn_exit")
        self.mn_exit.setIcon(QIcon(icon_exit))


        self.mn_rsa = QtWidgets.QAction(MainWindow)
        self.mn_rsa.setIcon(QIcon(icon_rsa))
        self.mn_rsa.setObjectName("mn_aes")
        self.mn_aes = QtWidgets.QAction(MainWindow)
        self.mn_aes.setIcon(QIcon(icon_aes))
        self.mn_aes.setObjectName("mn_rsa")
       
        self.mn_about = QtWidgets.QAction(MainWindow)

        self.mn_about.setIcon(QIcon(icon_about))
        self.mn_about.setObjectName("mn_about")
        self.mn_about.triggered.connect(self.about)

        self.mn_help = QtWidgets.QAction(MainWindow)
        self.mn_help.setIcon(QIcon(icon_help))
        self.mn_help.setObjectName("mn_help")
        self.actionRIPEMD160 = QtWidgets.QAction(MainWindow)
        self.actionRIPEMD160.setObjectName("actionRIPEMD160")
        
        self.mn_save = QtWidgets.QAction(MainWindow)
        self.mn_save.setIcon(QIcon(icon_save))
        self.mn_save.setObjectName("mn_save")
        
        self.menuFile.addAction(self.mn_open)
        
        self.menuFile.addAction(self.mn_save)
        self.menuFile.addSeparator()
        self.mn_exit.setShortcut('Ctrl+Q')
        self.mn_exit.triggered.connect(MainWindow.close)
        self.menuFile.addAction(self.mn_exit)

        self.menuAlgorithms.addSeparator()

        self.menuAlgorithms.addAction(self.mn_aes)
        self.menuAlgorithms.addAction(self.mn_rsa)

        self.menuHelp.addAction(self.mn_help)
        self.menuHelp.addSeparator()
        self.menuHelp.addAction(self.mn_about)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuAlgorithms.menuAction())
        self.menubar.addAction(self.menuHash.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "CHAA"))
        self.lbl_title.setText(_translate("MainWindow", "CHAA"))
        self.lbl_sub_title.setText(_translate("MainWindow", "Assemblage Hachage et Cryptographie Algorithme"))
        self.chk_md5.setText(_translate("MainWindow", "MD 5"))
        self.chk_sha1.setText(_translate("MainWindow", "SHA 1"))
        self.chk_sha256.setText(_translate("MainWindow", "SHA 256"))
        self.chk_sha384.setText(_translate("MainWindow", "SHA 384"))
        self.chk_sha512.setText(_translate("MainWindow", "SHA 512"))
       
        self.lbl_file.setText(_translate("MainWindow", "Open File"))
        self.btn_open.setText(_translate("MainWindow", "FIND"))
        self.btn_aes.setText(_translate("MainWindow", "AES"))
        self.btn_rsa.setText(_translate("MainWindow", "RSA"))
     
        self.lbl_saveas.setText(_translate("MainWindow", "Save File(s) as..."))
        self.lbl_supmti.setText(_translate("MainWindow", "SUP MTI"))
        self.btn_calculate.setText(_translate("MainWindow", "Calculate"))
        self.btn_exit.setText(_translate("MainWindow", "Exit"))
        self.lbl_names.setText(_translate("MainWindow", "Ghita & Mohammed"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuAlgorithms.setTitle(_translate("MainWindow", "Algorithms"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.mn_open.setText(_translate("MainWindow", "Open..."))

        self.action.setText(_translate("MainWindow", "---------------------------"))
        self.mn_exit.setText(_translate("MainWindow", "exit"))
        self.mn_rsa.setText(_translate("MainWindow", "RSA"))
        self.mn_aes.setText(_translate("MainWindow", "AES"))
        self.mn_about.setText(_translate("MainWindow", "CHAA Apropos de..."))
        self.mn_help.setText(_translate("MainWindow", "CHAA help..."))
        self.actionRIPEMD160.setText(_translate("MainWindow", "RIPEMD 160"))
        self.mn_save.setText(_translate("MainWindow", "Save..."))

    
    def open_file_dialog(self):
        fname= QFileDialog.getOpenFileName(None, "Open File for crypto-hash", "", "Text Files (*.txt);;All Files (*)")
        fh= open(fname[0], 'r')
        data= fh.read()
        return data
    
    def display_message(self):
        data= self.open_file_dialog()
        self.file_path.setText(data)
        
    def hash_calculate(self):

        data= self.file_path.toPlainText()

        if data=="":
            msg_box= QMessageBox()
            msg_box.setWindowTitle("Empty field.")
            msg_box.setWindowIcon(QIcon("./imgs/itachi-alt.ico"))
            msg_box.setIcon(QMessageBox.Information)
            msg_box.setText("text edit empty, Open file or create one in text edit!")
            msg_box.exec_()

        if self.chk_md5.isChecked():
            hash_object = hashlib.md5(data.encode())
            hex_dig = hash_object.hexdigest()
            self.lbl_md5.setText(hex_dig)
        else:
            self.lbl_md5.setText("")
       
        if self.chk_sha1.isChecked():
            hash_object = hashlib.sha1(data.encode())
            hex_dig = hash_object.hexdigest()
            self.lbl_sha1.setText(hex_dig)
        else:
            self.lbl_sha1.setText("")
       
        if self.chk_sha256.isChecked():
            hash_object = hashlib.sha256(data.encode())
            hex_dig = hash_object.hexdigest()
            self.lbl_256.setText(hex_dig)
        else:
            self.lbl_256.setText("")
       
        if self.chk_sha384.isChecked():
            hash_object = hashlib.sha384(data.encode())
            hex_dig = hash_object.hexdigest()
            self.lbl_386.setText(hex_dig)
        else:
            self.lbl_386.setText("")

        if self.chk_sha512.isChecked():
            hash_object = hashlib.sha512(data.encode())
            hex_dig = hash_object.hexdigest()
            self.lbl_512.setText(hex_dig)
        else:
            self.lbl_512.setText("")

    def msg_box_encrypt(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText('Information')
        msg.setInformativeText('File successfully encrypted.')
        msg.setWindowTitle('Info...')
        msg.exec_()

    def aes_crypt(self):
        """
        Note that the encrypt_file function in this example code uses CBC (Cipher Block Chaining) mode to encrypt the file. It also uses PKCS7 padding to ensure that the plaintext is a multiple of the block size. You may need to modify the encryption function depending on your specific requirements.
        """
        file_path, _ = QFileDialog.getOpenFileName(None, "Open File for aes encrypt", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            key = b'Sixteen byte key'
            cipher = AES.new(key, AES.MODE_EAX)
            with open(file_path, 'rb') as file:
                data = file.read()
                ciphertext, tag = cipher.encrypt_and_digest(data)

            encrypted_file_path, _ = QFileDialog.getSaveFileName(None, "Save File", "GM_aes_file", "Text Files (*.txt);;All Files (*)")
            if encrypted_file_path:
                with open(encrypted_file_path, 'wb') as file:
                    [ file.write(x) for x in (cipher.nonce, tag, ciphertext) ]
            
            self.msg_box_encrypt()       

    def rsa_crypt(self):
        file_name, _ = QFileDialog.getOpenFileName(None, "Select a file to encrypt",
                                                     "","Text Files (*.txt);; All Files (*)")
        if not file_name:
            return

        # generate RSA key pair
        key = RSA.generate(2048)

        # encrypt the file with the RSA public key
        with open(file_name, 'rb') as file:
            data = file.read()
            cipher = PKCS1_OAEP.new(key.publickey())
            encrypted_data = cipher.encrypt(data)

        # save the encrypted file with a new name
        new_file_name, _ = QFileDialog.getSaveFileName(None, "Save encrypted file as",
                                                        "GM_RSA", "All Files (*)")
        if not new_file_name:
            return
        with open(new_file_name, 'wb') as file:
            file.write(encrypted_data)

    def about(self):
            QMessageBox.about(None , "About...", "Version: 1.0.0 (system setup) \n\n\
                               Date: 2023-03-14 \n\
                               OS: Windows_NT x64 10.0.19045 \n\n\
                               Created by: Riti Rita, Laaraj Mohammed \n\
                               Orga.: SUP MTI\n")
   
    def helping(self):
            QMessageBox. about(None , "Help", "Version: 1.0.0 (system setup) \n\n\
                               Date: 2023-03-14 \n\
                               OS: Windows_NT x64 10.0.19045 \n\n\
                               Created by: Riti Rita, Laaraj Mohammed \n\
                               Orga.: SUP MTI\n")

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    MainWindow = QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

