from threading import Thread
from pathlib import Path
import time
from vuln import scan
import os, platform, sys
import shutil
import requests


def clear():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')



print("""
.%%%%%...%%%%%...%%%%%%..%%%%%%..%%%%%%..%%%%%%..%%..%%....%%.....%%%%..
.%%..%%..%%..%%..%%......%%......%%......%%......%%%.%%....%%....%%.....
.%%%%%...%%%%%...%%%%....%%%%....%%%%....%%%%....%%.%%%.....%.....%%%%..
.%%..%%..%%..%%..%%......%%......%%......%%......%%..%%..............%%.
.%%%%%...%%..%%..%%%%%%..%%%%%%..%%%%%%..%%%%%%..%%..%%...........%%%%..
........................................................................
.................%%%%%....%%%%...%%%%%...%%..%%...%%%%..................
.................%%..%%..%%..%%..%%..%%..%%.%%...%%.....................
.................%%..%%..%%..%%..%%%%%...%%%%.....%%%%..................
.................%%..%%..%%..%%..%%..%%..%%.%%.......%%.................
.................%%%%%....%%%%...%%..%%..%%..%%...%%%%..................
........................................................................
""")      

if not os.path.isdir("threads/"):
    os.makedirs("threads/")
else:
    shutil.rmtree("threads/")
    time.sleep(.5)
    os.makedirs("threads/")

while True:
    file = input("URLs file: ")

    if not Path(file).is_file():
        print("File does not exist, try again")
        break

    threads = int(input("\nThreads: "))

    useproxy = True if input(
        "\nUse proxy? (Y / N): ").lower() == "y" else False

    proxyfile = None

    freeproxy = False

    if useproxy:
        proxyfile = input("\nProxy file: ")
        if not Path(proxyfile).is_file():
            print("File does not exist, try again")
            break
        freeproxy = True if input(
            "\nAre you using free proxies? (more retries) (Y / N): ").lower(
            ) == "y" else False

    Threads = []
    try:
        with open(file) as infp:
            for i in range(threads):
                if not os.path.isdir(f"threads/{str(i)}/"):
                    os.makedirs(f"threads/{str(i)}/")
                else:
                    shutil.rmtree(f"threads/{str(i)}/")
                    time.sleep(.5)
                    os.makedirs(f"threads/{str(i)}/")  
                    
            files = [open(f'threads/{i}/input.txt', 'w') for i in range(threads)]
            for i, line in enumerate(infp):
                files[i % threads].write(line)
            for f in files:
                f.close()

        for i in range(threads):
            Threads.append(
                Thread(target=scan, args=(file, proxyfile, freeproxy, i)))

        clear()

        for x in Threads:
            x.daemon = True
            x.start()
            time.sleep(.2)

        for x in Threads:
            x.join()
            time.sleep(.2)
    except KeyboardInterrupt:
        shutil.rmtree(f"threads/")
        sys.exit()

    shutil.rmtree(f"threads/")

    print("\nScan finished")

    if Path(file.replace('.txt', '') + '-vuln.txt').is_file():
        print(
            f"\nTotal vulnerable sites found: {sum(1 for line in open(file.replace('.txt','') + '-vuln.txt'))}"
        )
    break

input("\nENTER to close")
