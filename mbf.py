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
