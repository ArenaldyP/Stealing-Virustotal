# System Information Collector

## Deskripsi
Program ini ditulis dalam bahasa C dan menggunakan API Windows untuk mengumpulkan informasi sistem, termasuk:
- Nama host komputer
- Versi OS Windows
- Arsitektur prosesor
- Jumlah prosesor
- Informasi drive logis
- Alamat IP dan informasi jaringan
- Alamat MAC
- Total dan penggunaan RAM
- Total dan ruang kosong pada disk

Setelah mengumpulkan informasi ini, program mengirimkannya ke VirusTotal sebagai komentar pada file tertentu menggunakan API mereka.

## Prasyarat
Sebelum menjalankan program ini, pastikan:
1. Anda memiliki Windows SDK terinstal untuk menggunakan API Windows.
2. Anda memiliki kunci API dari VirusTotal.
3. Anda telah menyertakan `VT_API_KEY` dan `FILE_ID` yang valid dalam kode.

## Cara Menggunakan
1. **Kompilasi kode** menggunakan MinGW atau Visual Studio:
   ```sh
   x86_64-w64-mingw32-g++ -o system_info.exe Stealing-Virustotal.c -lwinhttp -liphlpapi
   ```
2. **Jalankan program** dari terminal atau command prompt:
   ```sh
   system_info
   ```
3. Program akan menampilkan informasi sistem dan mencoba mengirimkannya ke VirusTotal.

## Fitur
- Menggunakan `WinHttp` untuk mengirim data melalui HTTP POST.
- Menggunakan `GetComputerNameA`, `GetVersionEx`, dan `GetSystemInfo` untuk mengambil informasi sistem dasar.
- Menggunakan `GetAdaptersInfo` untuk mendapatkan informasi jaringan.
- Menggunakan `GlobalMemoryStatusEx` untuk mendapatkan informasi RAM.
- Menggunakan `GetDiskFreeSpaceEx` untuk mendapatkan informasi disk.
- Menggunakan `WinHttpQueryHeaders` untuk memeriksa respons dari VirusTotal.

## Catatan Keamanan
- Jangan membagikan atau mengunggah kunci API secara publik.
- Pastikan Anda memiliki izin untuk mengakses dan mengirim informasi sistem ke layanan eksternal.

## Lisensi
Proyek ini dirilis di bawah lisensi MIT.

## Kontributor
Dikembangkan oleh seorang peneliti keamanan siber yang beretika.

