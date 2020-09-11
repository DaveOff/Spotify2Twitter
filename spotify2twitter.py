import os, sqlite3, requests, json, ctypes
import http.cookiejar as cookielib
from requests.utils import dict_from_cookiejar
from configparser import ConfigParser
from time import sleep
from ctypes import c_int,c_bool
from urllib.parse import quote

user32 = ctypes.WinDLL('user32', use_last_error = True)

EnumWindows = user32.EnumWindows
EnumChildWindows = user32.EnumChildWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))

GetWindowText = user32.GetWindowTextW
GetWindowTextLength = user32.GetWindowTextLengthW

clear = lambda: os.system('cls')

class spotify2twitter:

    newLine = "%0a"
    currentBio = "%23bestable" + newLine
    headphoneEmoji = "\xF0\x9F\x8E\xA7 "

    def __init__(self):
        firefoxConfig = ConfigParser()
        firefoxConfig.read(os.getenv('APPDATA')+r"\Mozilla\Firefox\profiles.ini")
        if firefoxConfig.has_option('Profile0', 'Path') is False :
            raise Exception("[Init] Firefox Profile Did Not Find!")
        self.cookie_jar = cookielib.CookieJar()
        self.firefox_profile = firefoxConfig.get('Profile0', 'Path')
        self.spotifyWindow = self.spotifyWindowTitle = None

    def get_cookies(self):
        path = os.getenv('APPDATA')+r"\Mozilla\Firefox\\"+self.firefox_profile.replace('/', "\\")+r"\cookies.sqlite"
        con = sqlite3.connect(path)
        cur = con.cursor()
        cur.execute("SELECT host, path, isSecure, expiry, name, value FROM moz_cookies WHERE host = '.twitter.com'")
        for item in cur.fetchall():
            c = cookielib.Cookie(0, item[4], item[5],
                None, False,
                item[0], item[0].startswith('.'), item[0].startswith('.'),
                item[1], False,
                item[2],
                item[3], item[3]=="",
                None, None, {})
            self.cookie_jar.set_cookie(c)
        cookies = dict_from_cookiejar(self.cookie_jar)
        if 'ct0' not in cookies :
            raise Exception("[Cookies] Token Not Found!")
        self.token = cookies['ct0']

    def run(self):  
        self.get_cookies()
        while self.spotifyWindow is None:
            self.print("[*] Open Spotify or Pause Music...", mclear=True)
            self.findWindow()
            sleep(1)
        self.findWindowTitle()
        cache = self.spotifyWindowTitle
        while True:
            self.findWindowTitle()
            if self.spotifyWindowTitle != cache and self.spotifyWindowTitle != "Spotify Free":
                cache = self.spotifyWindowTitle
                if("Advertisement" in self.spotifyWindowTitle or "Spotify" in self.spotifyWindowTitle): continue
                self.request(self.currentBio+self.headphoneEmoji+quote(cache))
                self.print("[+] " + cache)
            sleep(2)

    def findWindow(self):
        def foreach_window(hwnd, lParam):
            length = GetWindowTextLength(hwnd)
            if length <= 1 : return True
            mbuff = ctypes.create_unicode_buffer(length + 1)
            GetWindowText(hwnd, mbuff, length + 1)
            if("Spotify" in mbuff.value):
                self.spotifyWindow = hwnd
                self.print("[*] Searching For Music...", mclear=True)
                return False
            return True
        EnumWindows(EnumWindowsProc(foreach_window), 0)

    def findWindowTitle(self):
        length = GetWindowTextLength(self.spotifyWindow)
        buff = ctypes.create_unicode_buffer(100)
        GetWindowText(self.spotifyWindow, buff, length + 1)
        if length <= 1 : 
            self.setDefaultBio()
            raise Exception("[findWindowTitle] Exit!")
        self.spotifyWindowTitle = buff.value

    def setDefaultBio(self):
        self.request(self.currentBio)

    def request(self, text):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
            'x-twitter-active-user': 'yes',
            'x-csrf-token': self.token,
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'Referer': 'https://twitter.com/settings/profile',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0'
        }
        response = requests.post('https://api.twitter.com/1.1/account/update_profile.json', data="displayNameMaxLength=50&description="+text, cookies=self.cookie_jar, headers=headers)

        if response.ok is False :
            if response.status_code == 429 : raise Exception("[Request] Refresh Twitter Web Page")
            else : raise Exception("[Request] Something is Wrong!")
        try:
            json_object = json.loads(response.content)
        except ValueError as e:
            raise Exception("[Request] Json is Not Valid!")
        return json_object

    def print(self, text, mclear=False):
        if mclear == True: clear()
        print(text)

if __name__ == "__main__":
    ins = spotify2twitter()
    try :
        ins.run()
    except Exception as err:
        print("[Error]{}".format(err))
    except KeyboardInterrupt:
        ins.setDefaultBio()
        ins.print("Bye", mclear=True)
     
