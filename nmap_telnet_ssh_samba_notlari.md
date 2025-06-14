# Nmap, Telnet, SSH ve Samba Notları

## 🔍 Nmap (Network Mapper) Nedir?
Nmap, ağ taraması ve güvenlik testi için kullanılan güçlü bir araçtır.

### Nmap Ne İşe Yarar?
- Ağdaki cihazları keşfetme
- Açık portları tarama
- İşletim sistemi tespiti
- Güvenlik açığı analizi
- Saldırı simülasyonları

## 🔧 Nmap Kullanımı

### Temel Ağ Taraması
```bash
nmap 192.168.1.1
nmap 192.168.1.0/24
```

### Açık Portları Görmek
```bash
nmap -sS 192.168.1.1
nmap -sV 192.168.1.1
```

### İşletim Sistemi Tespiti
```bash
nmap -O 192.168.1.1
```

### Güvenlik Açığı Taraması
```bash
nmap --script=vuln 192.168.1.1
```

### Belirli Portları Tarama
```bash
nmap -p 80,443 192.168.1.1
nmap -p- 192.168.1.1
```

### Hızlı Tarama
```bash
nmap -T4 192.168.1.1
```

## 🔐 Telnet Nedir?
Telnet, TCP 23. port üzerinden şifrelenmemiş uzak bağlantı sağlar. Güvenli değildir.

### Telnet Kullanımı
```bash
telnet 192.168.1.1
exit
```

## 🔐 SSH Nedir?
SSH, TCP 22. port üzerinden güvenli bağlantı sağlar.

### SSH ile Bağlantı
```bash
ssh kullanıcı@192.168.1.1
ssh root@192.168.1.1
ssh -p 2222 root@192.168.1.1
exit
```

### SSH Anahtar Tabanlı Kimlik Doğrulama
Anahtar oluşturma:
```bash
ssh-keygen -t rsa -b 4096
```

Anahtarı sunucuya kopyalama:
```bash
ssh-copy-id kullanıcı@192.168.1.1
```

### SSH ile Dosya Transferi

#### SCP (Secure Copy)
```bash
scp dosya.txt kullanıcı@192.168.1.1:/hedef_klasör/
scp kullanıcı@192.168.1.1:/hedef_dosya.txt ./
```

#### SFTP
```bash
sftp kullanıcı@192.168.1.1
```

## 🔎 Telnet vs SSH

| Özellik           | Telnet | SSH  |
|------------------|--------|------|
| Şifreleme        | ❌ Yok | ✅ Var |
| Port             | 23     | 22   |
| Güvenlik         | ❌ Düşük | ✅ Yüksek |
| Kimlik Doğrulama | Sadece şifre | Şifre + Anahtar |

## 📁 Samba Portları

| Protokol | Port | Açıklama                 |
|----------|------|--------------------------|
| TCP      | 139  | NetBIOS Session Service  |
| TCP      | 445  | Microsoft-DS (SMB)       |
| UDP      | 137  | NetBIOS Name Service     |
| UDP      | 138  | NetBIOS Datagram Service |

### Samba Portlarını Görüntüleme
```bash
sudo netstat -tulnp | grep smbd
sudo ss -tulnp | grep smbd
```

### UFW ile Port Açma (Ubuntu)
```bash
sudo ufw allow 139/tcp
sudo ufw allow 445/tcp
sudo ufw allow 137/udp
sudo ufw allow 138/udp
sudo ufw reload
```

### Firewalld ile Port Açma (CentOS/RHEL)
```bash
sudo firewall-cmd --permanent --add-service=samba
sudo firewall-cmd --reload
```

## 📝 Sonuç
- **Nmap**, ağ analizi ve güvenlik denetimi için temel araçtır.
- **Telnet**, güvensizdir; SSH tercih edilmelidir.
- **SSH**, hem uzak bağlantı hem dosya aktarımı için uygundur.
- **Samba**, ağda dosya paylaşımı için yaygın olarak kullanılır.