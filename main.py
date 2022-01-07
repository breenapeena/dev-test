from threading import Thread
from pathlib import Path
import time
from vuln import scan
import os, platform, sys, glob
import shutil
import requests
import zipfile

def clear():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')

print("Checking for updates...")

update_check = requests.get("https://raw.githubusercontent.com/breenapeena/dev-test/main/version").text

if not os.path.isfile("version") or update_check != open("version").readlines()[0]:
    update = input("WARNING: This version is not up to date with current. Update? (Y / N): ")
    if update.lower() == "y":

        for f in glob.glob("*"):
            if os.path.isdir(f):
                shutil.rmtree(f)
            else:
                os.remove(f)

        with open("update.zip", "wb") as file:
            for data in requests.get("https://codeload.github.com/breenapeena/dev-test/zip/refs/heads/main", stream=True).raw:
                file.write(data)
        
        with zipfile.ZipFile("update.zip", 'r') as zip_ref:
            zip_ref.extractall()
        
        for file_name in os.listdir("dev-test-main"):
            shutil.move(os.path.join(os.listdir("dev-test-main"), file_name), os.path.abspath(os.getcwd()))        
 
            

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
