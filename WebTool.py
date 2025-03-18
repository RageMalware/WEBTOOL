import requests
import whois
import dns.resolver
import tweepy
import shodan
import re
import socket
import time
from bs4 import BeautifulSoup
import os
import hashlib
from collections import defaultdict
from colorama import init, Fore, Back, Style

# Colorama'yı başlat
init()

# Renkler
BASLIK_RENK = Fore.RED + Back.WHITE + Style.BRIGHT
BILGI_RENK = Fore.WHITE + Style.NORMAL
HATA_RENK = Fore.RED + Style.BRIGHT
BASARI_RENK = Fore.GREEN + Style.BRIGHT

# Kredi satırı
KREDI = Fore.YELLOW + "\n@leakturkey & @swarehackteam & @leakturkeymalware" + Style.RESET_ALL

def ekran_temizle():
    # İşletim sistemini kontrol et
    if os.name == 'nt':  # Windows
        os.system('cls')
    else:  # Linux, macOS ve diğer UNIX benzeri sistemler
        os.system('clear')

# WHOIS Bilgisi Toplama
def whois_bilgisi(domain):
    try:
        w = whois.whois(domain)
        print(BASLIK_RENK + "\nWHOIS Bilgisi:" + Style.RESET_ALL)
        print(f"Domain: {w.domain_name}")
        print(f"Kayıt Tarihi: {w.creation_date}")
        print(f"Son Güncelleme: {w.updated_date}")
        print(f"Son Kullanma Tarihi: {w.expiration_date}")
        print(f"Kayıt Sahibi: {w.registrar}")
        print(f"Name Servers: {w.name_servers}")
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# IP Adresi Coğrafi Konum Bilgisi
def ip_konum_bilgisi(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        veri = r.json()
        if veri["status"] == "success":
            print(BASLIK_RENK + "\nIP Coğrafi Konum Bilgisi:" + Style.RESET_ALL)
            print(f"IP: {veri['query']}")
            print(f"Ülke: {veri['country']}")
            print(f"Şehir: {veri['city']}")
            print(f"Zaman Dilimi: {veri['timezone']}")
            print(f"ISP: {veri['isp']}")
            print(f"Koordinatlar: {veri['lat']}, {veri['lon']}")
        else:
            print(HATA_RENK + f"Hata: {veri['message']}" + Style.RESET_ALL)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# DNS Bilgisi Toplama
def dns_bilgisi(domain):
    try:
        print(BASLIK_RENK + "\nDNS Bilgisi:" + Style.RESET_ALL)
        a_kaydi = dns.resolver.resolve(domain, 'A')
        print(f"A Kaydı: {[ip.to_text() for ip in a_kaydi]}")

        mx_kaydi = dns.resolver.resolve(domain, 'MX')
        print(f"MX Kaydı: {[mx.to_text() for mx in mx_kaydi]}")

        ns_kaydi = dns.resolver.resolve(domain, 'NS')
        print(f"NS Kaydı: {[ns.to_text() for ns in ns_kaydi]}")
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Port Tarama
def port_tarama(hedef_ip, baslangic_port, bitis_port):
    print(BASLIK_RENK + "\nPort Tarama:" + Style.RESET_ALL)
    for port in range(baslangic_port, bitis_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sonuc = sock.connect_ex((hedef_ip, port))
        if sonuc == 0:
            print(BASARI_RENK + f"[+] Port {port} açık" + Style.RESET_ALL)
        sock.close()

# Shodan ile Cihaz Tarama
def shodan_tarama(api_key, sorgu):
    try:
        api = shodan.Shodan(api_key)
        sonuclar = api.search(sorgu)
        print(BASLIK_RENK + "\nShodan Arama Sonuçları:" + Style.RESET_ALL)
        print(f"Toplam Sonuç: {sonuclar['total']}")
        for sonuc in sonuclar['matches']:
            print(f"IP: {sonuc['ip_str']}")
            print(f"Port: {sonuc['port']}")
            print(f"Organizasyon: {sonuc['org']}")
            print(f"Veri: {sonuc['data']}")
            print("-" * 40)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Dark Web Tarama (Tor Ağı Üzerinden)
def tor_tarama(onion_url):
    try:
        session = requests.session()
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        r = session.get(onion_url)
        soup = BeautifulSoup(r.text, 'html.parser')
        print(BASLIK_RENK + "\nDark Web Tarama:" + Style.RESET_ALL)
        print(soup.prettify())
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# E-posta Analizi
def email_analizi(email):
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print(BASARI_RENK + f"[+] Geçerli e-posta: {email}" + Style.RESET_ALL)
    else:
        print(HATA_RENK + f"[-] Geçersiz e-posta: {email}" + Style.RESET_ALL)

# Dosya Bütünlüğü Kontrolü
def dosya_butunluk_kontrolu(dizin, eski_hashler):
    print(BASLIK_RENK + "\nDosya Bütünlüğü Kontrolü:" + Style.RESET_ALL)
    for kok, _, dosyalar in os.walk(dizin):
        for dosya in dosyalar:
            dosya_yolu = os.path.join(kok, dosya)
            mevcut_hash = dosya_hash_hesapla(dosya_yolu)
            if dosya_yolu in eski_hashler:
                if eski_hashler[dosya_yolu] != mevcut_hash:
                    print(HATA_RENK + f"[!] Dosya değişti: {dosya_yolu}" + Style.RESET_ALL)
            else:
                print(BASARI_RENK + f"[+] Yeni dosya tespit edildi: {dosya_yolu}" + Style.RESET_ALL)
            eski_hashler[dosya_yolu] = mevcut_hash

def dosya_hash_hesapla(dosya_yolu):
    hasher = hashlib.md5()
    with open(dosya_yolu, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

# Sosyal Medya Profil Analizi
def sosyal_medya_profil_analizi(kullanici_adi):
    platformlar = {
        "Twitter": f"https://twitter.com/{kullanici_adi}",
        "Instagram": f"https://instagram.com/{kullanici_adi}",
        "GitHub": f"https://github.com/{kullanici_adi}",
        "LinkedIn": f"https://linkedin.com/in/{kullanici_adi}"
    }
    print(BASLIK_RENK + "\nSosyal Medya Profil Analizi:" + Style.RESET_ALL)
    for platform, url in platformlar.items():
        try:
            r = requests.get(url)
            if r.status_code == 200:
                print(BASARI_RENK + f"[+] {platform}: {url}" + Style.RESET_ALL)
            else:
                print(HATA_RENK + f"[-] {platform}: Profil bulunamadı" + Style.RESET_ALL)
        except Exception as e:
            print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Veri Sızıntısı Kontrolü
def veri_sizintisi_kontrolu(email):
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"User-Agent": "OSINT-Tool"})
        if r.status_code == 200:
            sizintilar = r.json()
            print(BASLIK_RENK + "\nVeri Sızıntısı Kontrolü:" + Style.RESET_ALL)
            for sizinti in sizintilar:
                print(f"Sızıntı: {sizinti['Name']}")
                print(f"Tarih: {sizinti['BreachDate']}")
                print("-" * 40)
        else:
            print(BASARI_RENK + f"[+] {email} adresi sızıntıya uğramamış." + Style.RESET_ALL)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Gelişmiş IP Analizi
def gelismis_ip_analizi(ip):
    try:
        r = requests.get(f"https://virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": "API_KEY"})
        if r.status_code == 200:
            veri = r.json()
            print(BASLIK_RENK + "\nGelişmiş IP Analizi:" + Style.RESET_ALL)
            print(f"Son Analiz Tarihi: {veri['data']['attributes']['last_analysis_date']}")
            print(f"Zararlı Bulunanlar: {veri['data']['attributes']['last_analysis_stats']['malicious']}")
        else:
            print(HATA_RENK + f"Hata: {r.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Twitter Hashtag Analizi
def twitter_hashtag_analizi(hashtag):
    try:
        # Twitter API anahtarlarınızı buraya girin
        consumer_key = 'YOUR_CONSUMER_KEY'
        consumer_secret = 'YOUR_CONSUMER_SECRET'
        access_token = 'YOUR_ACCESS_TOKEN'
        access_token_secret = 'YOUR_ACCESS_TOKEN_SECRET'

        auth = tweepy.OAuth1UserHandler(consumer_key, consumer_secret, access_token, access_token_secret)
        api = tweepy.API(auth)

        tweets = api.search_tweets(q=f"#{hashtag}", count=10)
        print(BASLIK_RENK + "\nTwitter Hashtag Analizi:" + Style.RESET_ALL)
        for tweet in tweets:
            print(f"Kullanıcı: {tweet.user.screen_name}")
            print(f"Tweet: {tweet.text}")
            print(f"Tarih: {tweet.created_at}")
            print("-" * 40)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Subdomain Keşfi
def subdomain_kesfi(domain):
    try:
        subdomainler = ["www", "mail", "ftp", "admin", "test"]
        print(BASLIK_RENK + "\nSubdomain Keşfi:" + Style.RESET_ALL)
        for sub in subdomainler:
            url = f"http://{sub}.{domain}"
            try:
                r = requests.get(url)
                if r.status_code == 200:
                    print(BASARI_RENK + f"[+] {url} bulundu" + Style.RESET_ALL)
            except requests.exceptions.RequestException:
                print(HATA_RENK + f"[-] {url} bulunamadı" + Style.RESET_ALL)
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# SSL/TLS Sertifika Analizi
def ssl_tls_analizi(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(BASLIK_RENK + "\nSSL/TLS Sertifika Analizi:" + Style.RESET_ALL)
                print(f"Sertifika: {cert}")
    except Exception as e:
        print(HATA_RENK + f"Hata: {e}" + Style.RESET_ALL)

# Ana Menü
def ana_menu():
    ekran_temizle()
    print(BASLIK_RENK + "\nİSTİHBARAT ARAÇLARI RageMalware Tarafından yazılmıştır" + Style.RESET_ALL)
    print(BILGI_RENK + """
    [1] WHOIS Bilgisi Toplama
    [2] IP Adresi Coğrafi Konum Bilgisi
    [3] DNS Bilgisi Toplama
    [4] Port Tarama
    [5] Shodan ile Cihaz Tarama
    [6] Dark Web Tarama (Tor Ağı Üzerinden)
    [7] E-posta Analizi
    [8] Dosya Bütünlüğü Kontrolü
    [9] Sosyal Medya Profil Analizi
    [10] Veri Sızıntısı Kontrolü
    [11] Gelişmiş IP Analizi
    [12] Twitter Hashtag Analizi
    [13] Subdomain Keşfi
    [14] SSL/TLS Sertifika Analizi
    [0] Çıkış
    """ + Style.RESET_ALL)

    secim = input("Yapmak istediğiniz işlemi seçin: ")

    if secim == "1":
        domain = input("WHOIS bilgisi alınacak domaini girin: ")
        whois_bilgisi(domain)
    elif secim == "2":
        ip = input("Coğrafi konum bilgisi alınacak IP adresini girin: ")
        ip_konum_bilgisi(ip)
    elif secim == "3":
        domain = input("DNS bilgisi alınacak domaini girin: ")
        dns_bilgisi(domain)
    elif secim == "4":
        hedef_ip = input("Hedef IP adresini girin: ")
        baslangic_port = int(input("Başlangıç portunu girin: "))
        bitis_port = int(input("Bitiş portunu girin: "))
        port_tarama(hedef_ip, baslangic_port, bitis_port)
    elif secim == "5":
        api_key = input("Shodan API anahtarınızı girin: ")
        sorgu = input("Shodan'da aranacak sorguyu girin (örneğin, 'Apache'): ")
        shodan_tarama(api_key, sorgu)
    elif secim == "6":
        onion_url = input(".onion URL'sini girin: ")
        tor_tarama(onion_url)
    elif secim == "7":
        email = input("Analiz edilecek e-posta adresini girin: ")
        email_analizi(email)
    elif secim == "8":
        dizin = input("İzlenecek dizini girin: ")
        eski_hashler = {}
        dosya_butunluk_kontrolu(dizin, eski_hashler)
    elif secim == "9":
        kullanici_adi = input("Analiz edilecek kullanıcı adını girin: ")
        sosyal_medya_profil_analizi(kullanici_adi)
    elif secim == "10":
        email = input("Kontrol edilecek e-posta adresini girin: ")
        veri_sizintisi_kontrolu(email)
    elif secim == "11":
        ip = input("Analiz edilecek IP adresini girin: ")
        gelismis_ip_analizi(ip)
    elif secim == "12":
        hashtag = input("Analiz edilecek hashtag'i girin: ")
        twitter_hashtag_analizi(hashtag)
    elif secim == "13":
        domain = input("Subdomain keşfi yapılacak domaini girin: ")
        subdomain_kesfi(domain)
    elif secim == "14":
        domain = input("SSL/TLS sertifika analizi yapılacak domaini girin: ")
        ssl_tls_analizi(domain)
    elif secim == "0":
        print(BASARI_RENK + "Çıkış yapılıyor..." + Style.RESET_ALL)
        exit()
    else:
        print(HATA_RENK + "Geçersiz seçim!" + Style.RESET_ALL)

    print(KREDI)
    input("\nDevam etmek için ENTER'a basın...")
    ana_menu()

# Programı Başlat
if __name__ == "__main__":
    ana_menu()