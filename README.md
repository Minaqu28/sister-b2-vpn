# sister-b2-vpn

Layer 3 Point-to-Point Virtual Private Network terenkripsi, ditulis **from
scratch** dalam bahasa **Go**.

Program ini menangkap IP packet yang keluar dari sebuah mesin Linux melalui
**TUN interface**, mengenkripsi dan mengautentikasinya dengan **AES-256-GCM**,
lalu mengirimkannya sebagai **datagram UDP** melewati jaringan publik/untrusted.
Endpoint di seberang melakukan kebalikannya, sehingga mesin tujuan menerima
IP packet tersebut sebagai *native traffic* biasa — bukan sebagai blob dari
internet.

Tidak ada library VPN siap pakai (WireGuard, OpenVPN, dsb.) maupun library
packet crafting (Scapy dsb.) yang dipakai. Seluruh format packet, penanganan
nonce, replay protection, dan pengelolaan TUN ditulis sendiri di atas standard
library Go dan syscall Linux.

---

## Fitur

| Fitur | Keterangan |
|---|---|
| VPN Layer 3 point-to-point | Yang ditunnel adalah IP packet, bukan Ethernet frame |
| TUN interface | Dibuat sendiri lewat `ioctl(TUNSETIFF)` pada `/dev/net/tun`, tanpa library |
| Transport UDP | Satu socket UDP per endpoint, membawa packet VPN buatan sendiri |
| Format packet sendiri | Header 16 byte: version, type, epoch, counter, length |
| Enkripsi + autentikasi | AES-256-GCM (AEAD), header ikut diautentikasi sebagai AAD |
| Key terpisah per arah | Dua sub-key diturunkan dari PSK dengan HKDF-Expand/HMAC-SHA256 |
| Nonce anti-berulang | Nonce = epoch acak per proses ‖ counter monoton per packet |
| Replay protection | Sliding window 64 packet + pemensiunan epoch lama |
| Penolakan packet tidak sah | Packet malformed, tag salah, dan replay dibuang dan dihitung |
| Peer roaming | Alamat peer diperbarui hanya setelah packet terautentikasi |
| Konfigurasi otomatis | Program memasang alamat, MTU, dan route lewat perintah `ip` |
| Routing antar subnet | Prefix LAN di seberang dapat diarahkan ke tunnel (`-route`) |
| Pemulihan otomatis | Tunnel pulih sendiri ketika salah satu endpoint restart |
| Statistik | Penghitung tx/rx dan alasan setiap packet dibuang |

### Cara kerja fitur utama

- **TUN Layer 3, bukan TAP.** Program membaca IP packet murni dari
  `/dev/net/tun` (tanpa Ethernet header), sehingga yang ditunnel adalah lalu
  lintas antar-jaringan IP, bukan satu broadcast domain seperti Layer 2.
  Kernel memperlakukan interface `vpn0` seperti interface biasa — tabel
  routing OS yang menentukan trafik mana yang masuk ke tunnel, bukan program
  VPN itu sendiri.
- **Alur kerja:** aplikasi menulis data → kernel merutekan ke `vpn0` →
  program membaca IP packet dari TUN → packet disusun jadi header VPN +
  ciphertext + tag → dikirim sebagai satu datagram UDP. Di sisi penerima,
  urutannya terbalik: datagram diterima → divalidasi → didekripsi → ditulis
  ke TUN → kernel meneruskannya ke aplikasi tujuan seolah trafik itu native.
- **UDP, bukan TCP.** Tunnel hanya perlu memindahkan datagram apa adanya;
  TCP di dalam TCP menimbulkan *TCP meltdown* — dua mekanisme retransmisi dan
  congestion control saling bertumpuk saat jaringan memburuk. TCP yang
  berjalan di dalam tunnel (mis. transfer file) tetap bekerja normal karena
  menangani retransmisinya sendiri dari ujung ke ujung.
- **Peer roaming.** Alamat UDP lawan bicara dicatat ulang setiap kali packet
  baru diterima, tetapi *hanya* setelah packet itu lolos verifikasi
  authentication tag (lihat bagian Kriptografi). Ini memungkinkan endpoint
  berpindah IP/port (mis. akibat NAT) tanpa konfigurasi ulang, tanpa membuka
  celah pembajakan tunnel lewat datagram palsu.
- **Konfigurasi & routing otomatis.** Program menjalankan sendiri `ip addr`,
  `ip link`, dan `ip route` untuk memasang alamat, MTU, dan rute tunnel, lalu
  mencatatnya ke log agar dapat direproduksi manual. Routing sengaja
  dipisahkan dari core tunnel: program tidak pernah memutuskan packet mana
  yang lewat tunnel, ia hanya memindahkan apa yang diserahkan tabel routing
  kernel. Prinsip inilah yang membuat bonus subnet berbeda tercapai tanpa
  mengubah satu baris pun kode enkripsi — cukup menambah entri `-route`.
- **Pemulihan otomatis.** Dibahas di bagian Kriptografi (mekanisme epoch):
  begitu satu endpoint restart, peer di seberang otomatis mengikuti epoch
  barunya tanpa perlu ikut di-restart, sementara packet dari sesi lama tetap
  tidak bisa diputar ulang.

### Format packet VPN

```
 0        1        2                    6                        14        16
+--------+--------+--------------------+------------------------+---------+
| Ver(1) | Typ(1) |      Epoch(4)      |      Counter(8)        | Len(2)  |
+--------+--------+--------------------+------------------------+---------+
|                     Ciphertext (Len byte)                               |
+-------------------------------------------------------------------------+
|                  Authentication Tag AES-GCM (16 byte)                   |
+-------------------------------------------------------------------------+
```

Header 16 byte dikirim tanpa enkripsi (penerima membutuhkannya untuk menyusun
nonce), tetapi ikut dijadikan **Additional Authenticated Data** pada GCM,
sehingga version/type/epoch/counter/length tidak dapat diubah di tengah jalan
tanpa membuat verifikasi tag gagal. Overhead tetap 32 byte per packet (16 byte
header + 16 byte tag).

---

## Kriptografi

### Algoritma: AES-256-GCM

Dipilih karena:

1. **AEAD** — confidentiality, integrity, dan authentication didapat sekaligus
   dari satu primitive, tanpa perlu menggabungkan sendiri cipher + MAC (sumber
   kesalahan klasik seperti urutan encrypt-then-MAC yang salah).
2. **Cocok untuk datagram** — tiap packet dienkripsi berdiri sendiri, sehingga
   UDP boleh menghilangkan/mengubah urutan packet tanpa merusak tunnel.
3. **Teruji luas** — algoritma yang sama dipakai TLS 1.3 dan IPsec, dipercepat
   AES-NI di CPU modern.
4. **Standard library Go** (`crypto/aes` + `crypto/cipher`) — tidak butuh
   dependency eksternal.

Tidak ada primitive kriptografi buatan sendiri; mode ECB tidak dipakai.

### Key

Pre-shared key 256-bit dari CSPRNG (`crypto/rand`), disimpan sebagai hex di
file permission `0600`. Key **tidak pernah dicetak**; yang tampil di log hanya
*fingerprint* 4-byte (SHA-256 terpotong) untuk memastikan kedua endpoint
memakai key yang sama.

Dari satu PSK yang sama, diturunkan **dua sub-key arah berbeda** lewat
HKDF-Expand/HMAC-SHA256 (`key_c2s` dan `key_s2c`). Tanpa ini, kedua endpoint
akan memulai dari counter yang sama dengan key yang sama — pasangan
(key, nonce) yang identik dipakai untuk dua plaintext berbeda, kesalahan fatal
pada GCM. Efek sampingnya: satu endpoint tidak dapat membuka packet buatannya
sendiri, sehingga packet tidak dapat dipantulkan ke pengirimnya.

### Nonce dan Counter

Nonce 96-bit = `Epoch (4 byte acak per proses) ‖ Counter (8 byte, naik atomik
per packet)`. Counter menjamin keunikan nonce selama proses hidup; epoch
menutup celah antar-restart — tanpa epoch, program yang di-restart akan
mengulang counter dari 1 dengan key yang sama, mengulang nonce.

### Authentication & replay protection

Setiap packet diverifikasi lewat **4 langkah berurutan** di sisi penerima:

1. Validasi struktur (panjang, version, type, counter≠0) — sebelum kriptografi disentuh.
2. Verifikasi authentication tag GCM, lalu dekripsi.
3. Cek **sliding window replay** 64 packet berbasis counter — **sengaja
   dijalankan setelah** langkah 2, supaya penyerang tidak bisa memajukan
   window dengan header yang dikarang sendiri.
4. Alamat peer baru dipercaya setelah packet lolos langkah 2 — sehingga tunnel
   tidak dapat dibajak dengan satu datagram palsu.

Ketika peer restart, epoch-nya berganti dan epoch lama dipensiunkan, sehingga
rekaman packet dari sesi sebelumnya tetap tidak dapat diputar ulang.

### Kenapa pre-shared key, bukan handshake Diffie-Hellman?

PSK sudah memenuhi kebutuhan tunnel point-to-point terenkripsi dengan mekanisme
yang dapat dijelaskan sepenuhnya. Konsekuensinya: skema ini **tidak memberi
forward secrecy**. Menambah handshake (mis. Noise/X25519 ala WireGuard) berarti
membangun state machine handshake penuh, yang berisiko mengorbankan kestabilan
requirement wajib — sehingga tidak dikerjakan.

---

## Cara Menjalankan

### Prasyarat

- **Go 1.22+**, **Linux** dengan modul `tun` (`/dev/net/tun`)
- Hak **root**/`CAP_NET_ADMIN`, dan `iproute2` (perintah `ip`)

### 1. Build dan buat key

```bash
git clone <repository>
cd sister-b2-vpn
make build     # -> ./bin/vpn
make genkey    # -> ./secret.key (fingerprint dicetak, key tidak pernah dicetak)
```

### 2. Jalankan di dua mesin Linux sungguhan

Salin `secret.key` ke mesin kedua lewat jalur aman (mis. `scp`), lalu:

```bash
# Mesin A
sudo ./bin/vpn server -key secret.key -listen 0.0.0.0:51820 \
  -tun-addr 10.9.0.1/24

# Mesin B
sudo ./bin/vpn client -key secret.key -peer <ip-mesin-a>:51820 \
  -tun-addr 10.9.0.2/24
```

Buktikan tunnel hidup: `ping 10.9.0.2` dari A, atau `ping 10.9.0.1` dari B.

### 3. Atau simulasikan dua endpoint di satu mesin (tanpa perangkat kedua)

Repo ini menyertakan lab **network namespace** Linux yang membangun 2 endpoint
+ router + 2 LAN pada subnet yang saling berbeda, seluruhnya di satu kernel:

```bash
sudo make lab-topology
```

Perintah ini membangun topologi lalu mencetak dua baris siap-salin. Jalankan
di **dua terminal terpisah**, biarkan keduanya tetap terbuka:

```bash
# Terminal 1 — endpoint A (server)
sudo ip netns exec vpn-a ./bin/vpn server -config configs/endpoint-a.conf

# Terminal 2 — endpoint B (client)
sudo ip netns exec vpn-b ./bin/vpn client -config configs/endpoint-b.conf
```

Endpoint A akan mencetak `tunnel siap: ... udp=10.10.1.2:51820`, dan begitu B
menyala, log A bertambah baris `alamat peer diperbarui` — bukti kedua endpoint
saling mengenali lewat packet yang sudah terautentikasi.

**Buktikan ping ICMP** (terminal ketiga):

```bash
sudo ip netns exec vpn-a ping -c 4 10.9.0.2
sudo ip netns exec vpn-b ping -c 4 10.9.0.1
```

**Buktikan transfer file ≥ 2 MB dengan checksum:**

```bash
make demo-file # buat 5 MB di transfer/endpoint-a/

# Terminal penerima
sudo ip netns exec vpn-b python3 scripts/filexfer.py recv \
  --listen 0.0.0.0:9000 --outdir transfer/endpoint-b/

# Terminal pengirim
sudo ip netns exec vpn-a python3 scripts/filexfer.py send \
  --to 10.9.0.2:9000 --file transfer/endpoint-a/data-uji.bin

make demo-check # bandingkan SHA-256 kedua sisi
```

`filexfer.py` mengirim nama file asli sebagai bagian dari transfer, jadi nama
berkas tidak berubah — boleh diganti berkas apa pun (mis. PDF), cukup salin ke
`transfer/endpoint-a/` lalu ganti nama file pada perintah `send`.

**Bonus — buktikan subnet berbeda:** kedua endpoint sengaja ditempatkan pada
subnet underlay berbeda (`10.10.1.0/24` dan `10.10.2.0/24`, dihubungkan lewat
router), dan masing-masing punya LAN sendiri di belakangnya
(`192.168.1.0/24` dan `192.168.2.0/24`):

```bash
sudo ip netns exec vpn-a ip route get 10.10.2.2   # -> via router, bukan satu segmen
sudo ip netns exec lan-a ping -c 4 192.168.2.10    # host LAN A -> host LAN B, lewat tunnel
```

`ttl=62` (bukan 64) pada hasil ping membuktikan packet melewati 2 hop routing
(endpoint A dan B).

**Bersihkan:** hentikan proses VPN dengan `Ctrl+C`, lalu `sudo make lab-down`.

Perintah bantu lain: `make help`.

### Opsi CLI

| Opsi | Bawaan | Keterangan |
|---|---|---|
| `-config` | — | Berkas konfigurasi `kunci = nilai` (lihat `configs/*.conf`) |
| `-key` | `secret.key` | File pre-shared key hex |
| `-listen` | `0.0.0.0:51820` (server) | Alamat bind UDP |
| `-peer` | — | Alamat UDP endpoint lawan; wajib untuk client |
| `-tun-addr` | — | Alamat TUN dalam CIDR, mis. `10.9.0.1/24` |
| `-mtu` | `1400` | MTU interface TUN (maksimum 1440) |
| `-route` | — | Prefix yang diarahkan ke tunnel; boleh diulang |
| `-ip-forward` | `false` | Menyalakan `net.ipv4.ip_forward`, untuk meneruskan trafik LAN |
| `-v` | `false` | Log per-packet |

Flag command line menimpa nilai di berkas `-config` bila keduanya diberikan.

---

## Struktur kode

```
cmd/vpn/            CLI: genkey / server / client + pembaca berkas konfigurasi
internal/
  crypto/            AES-256-GCM, HKDF, penyusunan nonce, pengelolaan key
  protocol/          format packet + parsing tervalidasi, sliding window replay
  transport/         socket UDP + peer roaming
  tun/               buka TUN lewat ioctl(TUNSETIFF), tanpa library
  netcfg/            pembungkus perintah `ip addr` / `ip link` / `ip route`
  vpn/               penyatuan semuanya: dua goroutine (TUN→UDP dan UDP→TUN)
configs/             berkas konfigurasi siap pakai untuk lab
scripts/             pembangun lab network namespace, pengirim/penerima file
transfer/            folder kerja untuk uji transfer file
```

`internal/` hanya dapat diimpor dari dalam modul ini (ditegakkan Go compiler),
menandai bahwa seluruh isinya adalah detail implementasi VPN ini, bukan
library untuk dipakai ulang.
