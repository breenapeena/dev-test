import requests
from errors import errors
import random
from colors import CGREEN, CRED, CEND, CYELLOW


def gen_proxy(proxyfile):
    return random.choice(open(proxyfile).readlines()).rstrip()


def add_vuln(filename, dork):
    with open(filename.replace('.txt', '') + "-vuln.txt",
              "a",
              encoding='windows-1252') as file:
        file.write(f"{dork}\n")


def random_dork(idx):
    while True:
        try:
            with open(f"threads/{idx}/input.txt", "r") as used:
                data = used.readlines()
                if len(data) < 0:
                    return None

            with open(f"threads/{idx}/input.txt", "w") as used:
                used.write(''.join(data[1:]))
                if '?' not in data[0]:
                    return None
            return data[0].rstrip()
        except:
            return None

def scan(filename=None, proxyfile=None, freeproxy=False, idx=0):
    try:
        while True:
            dork = random_dork(idx)
            if dork == None:
                break
            while True:
                global response
                response = None
                global RETRY_LIMIT
                if freeproxy == True:
                    RETRY_LIMIT = 5
                else:
                    RETRY_LIMIT = 3
                RETRYS = 0
                timeout = 15 if freeproxy == True else 6
                try:
                    if proxyfile != None:
                        proxy = gen_proxy(proxyfile)
                        response = requests.get(dork + "'",
                                                timeout=timeout,
                                                proxies={
                                                    "http": proxy,
                                                    "https": proxy
                                                })
                    else:
                        response = requests.get(dork + "'", timeout=timeout)

                    try:
                        data = response.text
                    except:
                        break

                    if any(error in data for error in errors):
                        print(CGREEN + "+ " + dork + CEND)
                        add_vuln(filename, dork + "'")
                    else:
                        print(CRED + "- " + dork + CEND)
                    break

                except requests.exceptions.ProxyError:
                    print(CYELLOW + "Proxy err | retry" + CEND)
                    pass
                except requests.exceptions.Timeout:
                    if proxyfile == None:
                        print(CRED + "Timeout error with no proxy, skipping")
                        break
                    else:
                        if RETRYS >= RETRY_LIMIT:
                            break
                        else:
                            print(CYELLOW + "Proxy err | retry" + CEND)
                            RETRYS += 1
                        pass
                except requests.exceptions.RequestException:
                    print(CRED + "- " + dork + CEND)
                    break
    except Exception as e:
        print(e)
        pass
