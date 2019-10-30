#Welcome to my SnortIPS script. I am Argyris Koudounas, a bachelor student who worked on this script as a part of my thesis on SDN security.
#In the following lines, you will have to change specific parts, mostly rule IDs and "if" statements, in order to make this script work for your case.
#You should adjust the following variables: comm, tcpRules, nmapRules. Also, change all the "if" statements that are related to those.

import pexpect
import time

while True:
    print("Welcome to Simple Snort IPS(SSIPS), select your actions: \n")
    print("1-Interface monitor\n2-Select iptables rule option \nPress 'ctrl-c' to exit")
    selection = input("")

    if selection == '1':
        iface = input("Enter interface to monitor: ")        
        comm = "sudo snort -A console -i '{0}' -u snort -g snort -c /etc/snort/snort.conf".format(iface)
        i = 0
        pingFlag = 0
        tcpFlag = 0
        nmapFlag = 0
        tcpRules = ["[1:10000021:0]", "[1:10000022:0]", "[1:10000025:0]", "10000926", "[1:10000030:0]"]
        nmapRules = ["[1:10001136:1]", "[1:1000137:1]", "[1:1000138:1]", "[1:1000139:1]", "[1:1000140:1]", "[1:1000141:1]"]


        child = pexpect.spawn(comm)

        while True:
            try:
                child.expect('\r\n', timeout=120000)
                print(child.before)

        #Checks output for specific alert code and acts
                for line in str(child.before).split("/r"):
                    #Ping attack check
                    for word in line.split(" "):

                        if word == "[1:10000002:1]":
                            pingFlag = pingFlag + 1
                            #print("PING TEST")
                            break
                        if pingFlag > 5000:
                            print("Suspicious ICMP packets - select action [0-nothing, 1-block traffic] ")
                            action = input("")
                            if action == 0:
                                pingFlag = 0;

                                continue
                            else:

                                reject_AllTrafic = "sudo iptables -A INPUT -p icmp -i '{0}' -j DROP".format(iface)
                                child2 = pexpect.spawn(reject_AllTrafic)
                                print("IPS: All Traffic Towards Server has been cut")
                                pingFlag = 0;
                                continue
                    #TCP attacks general solution
                    for word in line.split(" "):
                        for lex in tcpRules:
                            if word == lex:
                                tcpFlag = tcpFlag + 1
                                #print("TCP TEST")

                                continue

                            if tcpFlag > 20000:
                                print("Suspicious TCP packets - select action [0-nothing, 1-block traffic] ")
                                action = input("")
                                if action == 0:
                                    tcpFlag = 0

                                    continue
                                else:

                                    reject_AllTrafic = "sudo iptables -A INPUT -p tcp -i '{0}' -j DROP".format(iface)
                                    child2 = pexpect.spawn(reject_AllTrafic)
                                    print("IPS: All Traffic Towards Server has been cut")
                                    tcpFlag = 0
                                    continue
                    #Nmap detection
                    for word in line.split(" "):
                        for lex in nmapRules:
                            if word == lex:
                                nmapFlag = nmapFlag + 1
                                print("NMAP TEST")

                                continue

                            if nmapFlag > 3:
                                print("Nmap XMAS Scan - select action [0-nothing, 1-block traffic] ")
                                action = input("")
                                if action == 0:
                                    nmapFlag = 0

                                    continue
                                else:

                                    reject_AllTrafic = "iptables -A INPUT -i '{0}' -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j DROP".format(iface)
                                    child2 = pexpect.spawn(reject_AllTrafic)
                                    print("IPS: All Traffic Towards Server has been cut")
                                    nmapFlag = 0
                                    continue
                    i = i + 1
                    if i >3:
                        i = 0
                        break;
                    #if tcpFlag == 0:
                     #   break;
            except (KeyboardInterrupt, SystemExit):
                print("\nExiting...\n")
                break;
            except NameError:
                print("\nWrong interface!\n")
                break;
            except pexpect.EOF:
                print("\nPexpect error, quiting...\n")
                break

    elif selection== '2':
        inpt = input("1-Accept or block traffic on specific interface\n2-Accept or block traffic on specific interface, from specific address\n3-Accept or block traffic on specific interface from specific address, on specific port\n4-Insert manual rule\n")
        if inpt=='4':
            while True:
                try:

                    comm = input("Insert iptables rule: \n")
                    child = pexpect.spawn(comm)
                    while True:
                        child.expect('\n', timeout=120000)
                        print(child.before)
                        print("Rule inserted\n")
                        time.sleep(1)

                        answ = input("Do you want to save rule permanently? (y/n)")
                        if answ=='y' or answ=='Y':
                            child = pexpect.spawn("sudo invoke-rc.d iptables-persistent save")
                            print(child.before)
                        else:
                            break;

                except (KeyboardInterrupt, SystemExit):
                    break;

                except pexpect.EOF:
                    print("Pexpect error, quiting...\n")
                    break;

                except SyntaxError:
                    print("Error in command... \n")
                    break;
        elif inpt=='1':
            while True:
                try:

                    iface = input("Insert interface you would like to target:\n")
                    selection = input("1-Accept all traffic on {0} 2-Reject all traffic on {0}\n".format(iface))

                    if selection=='1':
                        comm = "sudo iptables -A INPUT -i '{0}' -j ACCEPT && sudo iptables -D INPUT -i '{0}' -j DROP ".format(iface)
                        child2 = pexpect.spawn(comm)
                        print(child2.before)
                        time.sleep(1)

                    else:
                        comm = "sudo iptables -A INPUT -i '{0}' -j DROP".format(iface)
                        child2 = pexpect.spawn(comm)
                        print(child2.before)
                        time.sleep(1)

                    choice = input("Do you want to permanently save those rules?(y/n)\n")
                    if choice == 'y' or choice == 'Y':
                        child3 = pexpect.spawn("sudo invoke-rc.d iptables-persistent save")
                        print(child3.before)
                        break;


                except (KeyboardInterrupt, SystemExit):
                    break;

                except pexpect.EOF:
                    print("Pexpect error, quiting...\n")
                    break;

                except SyntaxError:
                    print("Error in command... \n")
                    break;

        elif inpt=='2':
            while True:
                try:
                    iface = input("Insert interface you would like to target:\n")
                    addr = input("Insert address you would like to target:\n")
                    selection = input("1-Accept all traffic on {0} from address {1}\n2-Reject all traffic on {0} from address {1}".format(iface, addr))

                except (KeyboardInterrupt, SystemExit):
                    break;

                except pexpect.EOF:
                    print("Pexpect error, quiting...\n")
                    break;

                except SyntaxError:
                    print("Error in command... \n")
                    break;

        elif inpt=='3':
            while True:
                try:
                    iface = input("Insert interface you would like to target:\n")
                    addr = input("Insert address you would like to target:\n")
                    port = input("Insert port you would like to target:")
                    selection = input("1-Accept all traffic on {0} from address {1} on port {2}\n2-Reject all traffic on {0} from address {1} on port {2}".format(iface, addr, port))

                except (KeyboardInterrupt, SystemExit):
                    break;

                except pexpect.EOF:
                    print("Pexpect error, quiting...\n")
                    break;

                except SyntaxError:
                    print("Error in command... \n")
                    break;

    else:
        print("\nPlease enter one of the 2 options")
        time.sleep(0.7)

