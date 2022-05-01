from async_timeout import timeout
import scapy.all as scapy
from rich.console import Console
import time
console = Console()

banner = '''
[red]
    ===============================================================================
      [#6a27f9]
             __        __   __  ___          ___ ___       __   __       
            / _` |__| /  \ /__`  |     |\ | |__   |  |  | /  \ |__) |__/ 
            \__> |  | \__/ .__/  |     | \| |___  |  |/\| \__/ |  \ |  \ 
           [red]                                                             
    =================================================================================
    
    ==========         [green]CREATED BY = >   [red]                  ===============
               [#d1ff1c]                                                   
            ==                                                        ==  
            ==                       __                               ==
            ==                      (_  |_   _. |_  o ._              ==
            ==                      __) | | (_| |_) | |               ==
            ==          Version = >                                   ==
            ==                      v1.0                              ==
            ============================================================

'''
console.print(banner)
time.sleep(2)

data = input("\033[1;33;49m Enter Ip Range For Scan [+] = ")


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    arpEther = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpMessage = arpEther/arpRequest
    accepted = scapy.srp(arpMessage, timeout=1, verbose=False)[0]
    clients = []
    for item in accepted:
        dics = {"ip": item[1].psrc, "mac": item[1].hwsrc}
        clients.append(dics)
    return clients


def printing(result):
    console.print(
        "[#be25ed]Ip\t\t\t\tMac \n[blue]---------------------------------------------------------")
    for client in result:
        print(client['ip'], "\t\t\t",  client['mac'])


scan_result = scan(data)


printing(scan_result)
