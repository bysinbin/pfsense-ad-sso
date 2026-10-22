# Posea AD SSO for pfSense 🚀
### Kurumsal Active Directory Single Sign-On (AD SSO) ve Kimlik Eşleme Paketi

[![pfSense](https://img.shields.io/badge/pfSense-2.7%20%7C%20Plus-blue.svg)](https://www.pfsense.org/)
[![FreeBSD](https://img.shields.io/badge/FreeBSD-14%20%7C%2015-red.svg)](https://www.freebsd.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Posea AD SSO**, pfSense güvenlik duvarı üzerinde ağdaki istemci IP ve MAC adreslerini Microsoft Active Directory kullanıcıları ve güvenlik gruplarıyla anlık olarak eşleştiren yeni nesil bir SSO paketidir.

PoseaFilter UTM Web Filter ve **5651 Sayılı Kanun** uyumlu loglama gereksinimleri için eksiksiz kullanıcı kimliği altyapısı sağlar.

---

## 🌟 Öne Çıkan Özellikler

### 1. İki Farklı Çalışma Modu (Dual-Mode Architecture)

* **Mod 2: Sabit Bilgisayar - Kullanıcı Eşleme Modu (Önerilen - DC Yüksüz)**
  * Şirketlerde çalışanların kendi masalarında sabit bilgisayarları kullandığı yapılar için optimize edilmiştir.
  * Domain Controller'a (DC) sürekli login/logout sorgusu atmaz; DC işlemci ve ağ yükünü sıfıra indirir.
  * pfSense DHCP Leases (`dhcpd.leases`) ve ARP tablosundan bilgisayarları otomatik keşfeder.
  * Active Directory bilgisayar nesnelerinden (`CN=Computers`) veya bilgisayar adından (`PC-AHMET` -> `ahmet`) tek tıkla otomatik eşleme yapar.
  * **Yönetici (Administrator) Gezici İstisnası**: Yöneticiler herhangi bir bilgisayardan oturum açtığında sabit kullanıcı kuralı geçici olarak askıya alınır ve oturum Administrator olarak etiketlenir.

* **Mod 1: Dinamik Güvenlik Olayı Dinleme Modu (FSSO / Event Log 4624-4634)**
  * Gezici kullanıcıların veya ortak kullanılan bilgisayarların bulunduğu ortamlar için uygundur.
  * Domain Controller Güvenlik Olay Günlüklerini (Event ID 4624 - Logon, Event ID 4634/4647 - Logoff, Kerberos) takip eder.
  * Kullanıcı oturum açtığı anda IP ile kullanıcıyı eşler, çıkış yaptığında oturumu sonlandırır.

### 2. Derin Active Directory LDAP Entegrasyonu
* Kullanıcının Adı Soyadı (`displayName`), Departmanı ve üye olduğu tüm güvenlik gruplarını (`memberOf`) anında çeker ve yerel bellekte önbelleğe alır.
* LDAPS (SSL Port 636) ve standart LDAP (Port 389) destekler.

### 3. PoseaFilter UTM ve 5651 Loglama Entegrasyonu
* **PoseaFilter UTM Entegrasyonu**: Web filtreleme motorunun IP bazlı değil, doğrudan kullanıcı (`User: ahmet.yilmaz`) veya grup (`Group: Muhasebe`) bazlı kural ve log üretmesini sağlar.
* **5651 Kanun Uyumluluğu**: 5651 sayılı kanun gereği tutulması zorunlu olan IP, MAC, Kullanıcı Kimliği, Zaman ve Hedef eşleşmesinde gerçek kullanıcı kimliğini sağlar.
* **Yüksek Hızlı IPC Soketi**: `/var/run/posea_sso.sock` Unix soketi üzerinden mikrosaniye hızında IP -> Kullanıcı sorgulaması sunar.

---

## ⚡ Hızlı Kurulum

pfSense cihazınızın terminaline (SSH veya Console Option 8) girerek aşağıdaki komutu çalıştırmanız yeterlidir:

```sh
fetch -q -o - https://raw.githubusercontent.com/bysinbin/pfsense-ad-sso/main/scripts/install.sh | sh
```

Kurulum tamamlandığında pfSense WebGUI üzerinde **Services > Active Directory SSO** menüsü aktif hale gelir.

---

## 🖥️ WebGUI Sekmeleri

1. **General Settings**: SSO servisini açıp kapatma, Mod seçimi (Mod 1 / Mod 2), Domain Controller IP, LDAP portu, Base DN ve servis hesabı kimlik bilgileri.
2. **Active Sessions**: Canlı IP, MAC, Hostname, AD Kullanıcı, Adı Soyadı, Departman ve Grup üyeliklerini gösteren gerçek zamanlı oturum tablosu.
3. **Computer Bindings (Mod 2)**: Ağda keşfedilen tüm cihazları listeleyen ve tek tıkla kullanıcı ataması yapılmasını sağlayan görsel yönetim tablosu.
4. **AD Diagnostic & Test**: Active Directory bağlantısını, LDAP kimlik doğrulamasını (Bind), Base DN okuma izinlerini ve kullanıcı sorgulamasını tek tıkla test eden teşhis aracı.

---

## 💻 Komut Satırı (CLI) Araçları

```sh
# Belirli bir IP adresindeki kullanıcıyı sorgulama
php /usr/local/pkg/sso_client.php 192.168.2.170

# Tüm aktif oturumları listeleme
php /usr/local/pkg/sso_client.php --list

# Geçici yönetici geçersiz kılma (Administrator Override)
php /usr/local/pkg/sso_client.php --override 192.168.2.170 administrator
```

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) altında dağıtılmaktadır.
