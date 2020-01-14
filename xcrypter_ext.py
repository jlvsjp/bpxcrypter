#-*- coding:utf-8 -*-

from burp import IBurpExtender
from burp import ITextEditor
from burp import IParameter
from burp import IContextMenuFactory

from javax.swing import (JFrame, JMenuItem, JPanel, JSplitPane, JTextPane,
                         JScrollPane, JLabel, SwingConstants, JTextField,
                         JButton, JTextArea)

from javax.swing.border import EmptyBorder
from java.awt import (BorderLayout, GridLayout, Color, FlowLayout, Dimension,
                      GridBagLayout, GridBagConstraints)


from java.util import ArrayList
from java.io import PrintWriter
import array
import socket


global BP_STDOUT
global BP_STDERR

BP_STDOUT = None
BP_STDERR = None


LOCAL_IPC = ("127.0.0.1", 9999)


def jbytes_to_str(jbytes):
    r = ""
    for char in jbytes:
        r += chr(char & 255)
    return r


class MyPanel(JSplitPane):

    def __init__(self, scannerInstance):
        self.scannerInstance = scannerInstance
        JSplitPane.__init__(self, JSplitPane.VERTICAL_SPLIT)
        # super(MyPanel, self).__init__(self, JSplitPane.VERTICAL_SPLIT)
        # self.setSize(640, 460)
        self.setBorder(EmptyBorder(20, 20, 20, 20))

        self.topPanel = JPanel(BorderLayout(10, 10))
        self.topPanel.setBorder(EmptyBorder(0, 0, 10, 0))
        # self.topPanel.setBackground(Color.blue)

        self.bottomPanel = JPanel()
        self.bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))
        # self.bottomPanel.setBackground(Color.yellow)

        self.bottomPanel.setPreferredSize(Dimension(580, 40))
        # plain
        self.plainPanel = JPanel(BorderLayout(10, 10))

        self.plainTextPane = JTextArea()
        self.plainTextPane.setLineWrap(True)
        self.plainTextPane.setEditable(True)

        self.plainScrollPane = JScrollPane(self.plainTextPane)
        self.plainScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)

        self.plainPanel.add(JLabel("PLAIN:", SwingConstants.CENTER), BorderLayout.PAGE_START)
        self.plainPanel.add(self.plainScrollPane, BorderLayout.CENTER)

        self.topPanel.add(self.plainPanel, BorderLayout.LINE_START)

        # button
        self.btnsPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()

        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridx = 0
        gbc.gridy = 0
        self.btnsPanel.add(JButton("=Encrypt=>", actionPerformed=self.encrypt), gbc)


        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridx = 0
        gbc.gridy = 1
        self.btnsPanel.add(JButton("<=Decrypt=", actionPerformed=self.decrypt), gbc)

        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridheight = 2
        gbc.ipadx = 10
        self.btnsPanel.add(JButton("SIGN", actionPerformed=self.sign), gbc)

        # b_enc.setPreferredSize(Dimension(30, 20))
        # b_dec.setPreferredSize(Dimension(30, 20))

        self.topPanel.add(self.btnsPanel, BorderLayout.CENTER)

        # cipher
        self.cipherPanel = JPanel(BorderLayout(10, 10))

        self.cipherTextPane = JTextArea()
        self.cipherTextPane.setLineWrap(True)
        self.cipherTextPane.setEditable(True)

        self.cipherScrollPane = JScrollPane(self.cipherTextPane)
        self.cipherScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)

        self.cipherPanel.add(JLabel("CIPHER:", SwingConstants.CENTER), BorderLayout.PAGE_START)
        self.cipherPanel.add(self.cipherScrollPane, BorderLayout.CENTER)

        self.topPanel.add(self.cipherPanel, BorderLayout.LINE_END)

        self.signPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.signPanel.add(JLabel("SIGN:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.signField = JTextField(50)
        self.signPanel.add(self.signField)

        self.bottomPanel.add(self.signPanel)

        self.plainPanel.setPreferredSize(Dimension(260, 400))
        self.btnsPanel.setPreferredSize(Dimension(80, 400))
        self.cipherPanel.setPreferredSize(Dimension(260, 400))

        self.setTopComponent(self.topPanel)
        self.setBottomComponent(self.bottomPanel)


    def setPlain(self, plain):
        if plain:
            self.plainTextPane.setText(plain.decode("utf-8"))

    def setCipher(self, cipher):
        self.cipherTextPane.setText(cipher)

    def setSignature(self, sign):
        self.signField.setText(sign)

    def unicode_to_str(self, content):
        data = ""
        for i in content:
            data += chr(ord(i))
        return data


    def get_real_content(self, content):
        s_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        handled_cnt = None
        data = self.unicode_to_str(content)
        try:
            s_client.connect(LOCAL_IPC)
            s_client.send(data)
            handled_cnt = ""

            while True:
                _sp = s_client.recv(1024)
                if _sp and len(_sp) > 0:
                    handled_cnt += _sp

                    if len(_sp) < 1024:
                        break
                else:
                    break

        except socket.error:
            BP_STDERR.println("fail to connect local IPC service.")

        s_client.close()
        # BP_STDOUT.println("get_real_content - %s" % handled_cnt.decode("utf-8"))
        return handled_cnt if handled_cnt and len(handled_cnt) > 0 else None


    def encrypt(self, event):
        plain = self.plainTextPane.getText()
        # BP_STDERR.println("plain type - %s" % type(plain))
        result = self.get_real_content(b"\x01" + plain)
        self.setCipher(result)


    def decrypt(self, event, is_req=None):
        cipher = self.cipherTextPane.getText()
        # BP_STDERR.println("cipher type - %s" % type(cipher))
        flag = b"\x02" if is_req is True else b"\x03" if is_req is False else b"\x00"
        result = self.get_real_content(flag + cipher)
        self.setPlain(result)


    def sign(self, event):
        text = self.plainTextPane.getText()
        # BP_STDERR.println("sign func called! - %s" % text)
        result = self.get_real_content(b"\x04" + text)
        self.setSignature(result)


class BurpExtender(IBurpExtender, ITextEditor):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        global BP_STDOUT
        global BP_STDERR
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("burp_X_crypter")

        self.scannerMenu = MyMenu(self)
        self.xpannel = MyPanel(self)

        callbacks.registerContextMenuFactory(self.scannerMenu)
        callbacks.customizeUiComponent(self.xpannel)

        BP_STDOUT = PrintWriter(callbacks.getStdout(), True)
        BP_STDERR = PrintWriter(callbacks.getStderr(), True)



    # implement IMessageEditorTabFactory
    #

class MyMenu(IContextMenuFactory):
    def __init__(self, scannerInstance):
        self.scannerInstance = scannerInstance

    def createMenuItems(self, contextMenuInvocation):
        self.contextMenuInvocation = contextMenuInvocation
        menuItems = ArrayList()
        menuItems.add(JMenuItem("[XCrypt]", actionPerformed=self.x_event))
        return menuItems

    def show_pannel(self):
        # BP_STDOUT.println("Event code: %s" % self.contextMenuInvocation.getInputEvent())
        # self.scannerInstance.show_pannel.show()
        window = JFrame()
        window.setLayout(None)
        window.setTitle("Xcrpter")
        window.setSize(720, 540)
        window.setLocationRelativeTo(None)
        window.setResizable(True)
        window.setContentPane(self.scannerInstance.xpannel)
        window.setVisible(True)

        self.scannerInstance.xpannel.setPlain("")
        self.scannerInstance.xpannel.setVisible(True)


    def x_event(self, event):
        self.show_pannel()
        # BP_STDOUT.println("Event code: %s" % self.contextMenuInvocation.getInputEvent())
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages():

            # 4 - proxy
            # 64 - repeater
            # BP_STDOUT.println("ToolFlag: %s" % self.contextMenuInvocation.getToolFlag())

            InvocationContext = int(self.contextMenuInvocation.getInvocationContext())
            # BP_STDOUT.println("InvocationContext: %s" % InvocationContext)

            selected_txt = ""

            # BP_STDOUT.println("request string: %s" % selected_txt)
            selectedBounds = [i for i in self.contextMenuInvocation.getSelectionBounds()]

            if InvocationContext == 0 or InvocationContext == 2:
                req = selectedMessage.getRequest()

                for char in req:
                    selected_txt += chr(char & 255)

                # BP_STDOUT.println("selected request string: %s" % selected_txt[selectedBounds[0]: selectedBounds[1]])

                self.scannerInstance.xpannel.setCipher(selected_txt[selectedBounds[0]: selectedBounds[1]])
                self.scannerInstance.xpannel.decrypt(event, is_req=True)

            elif InvocationContext == 1 or InvocationContext == 3:
                resp = selectedMessage.getResponse()

                for char in resp:
                    selected_txt += chr(char & 255)

                # BP_STDOUT.println("selected request string: %s" % selected_txt[selectedBounds[0]: selectedBounds[1]])

                self.scannerInstance.xpannel.setCipher(selected_txt[selectedBounds[0]: selectedBounds[1]])
                self.scannerInstance.xpannel.decrypt(event, is_req=False)
