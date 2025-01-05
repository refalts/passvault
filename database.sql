CREATE DATABASE IF NOT EXISTS e_passport;

USE e_passport;

-- Tabel admins untuk menyimpan data admin
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL
);

-- Tabel users untuk menyimpan data pengguna biasa
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL
);

-- Tabel pengajuan untuk menyimpan data pengajuan paspor
CREATE TABLE IF NOT EXISTS pengajuan (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nik VARCHAR(20) NOT NULL,
    nama VARCHAR(255) NOT NULL,
    jenis_kelamin ENUM('Laki-laki', 'Perempuan') NOT NULL,
    tempat_lahir VARCHAR(255) NOT NULL,
    tanggal_lahir DATE NOT NULL,
    agama ENUM('Islam', 'Kristen', 'Katolik', 'Buddha', 'Hindu', 'Konghcu') NOT NULL,
    alamat TEXT NOT NULL,
    nomor_telepon VARCHAR(15) NOT NULL,
    email VARCHAR(255) NOT NULL,
    ktp_file_path VARCHAR(255) NOT NULL,
    status ENUM('Menunggu Verifikasi', 'Telah Diverifikasi', 'Selesai') NOT NULL DEFAULT 'Menunggu Verifikasi',
    tanggal_jadwal_foto DATE,
);

-- Tabel untuk menyimpan file upload lainnya (misalnya file foto atau berkas lain)
CREATE TABLE IF NOT EXISTS uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pengajuan_id INT NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    FOREIGN KEY (pengajuan_id) REFERENCES pengajuan(id) ON DELETE CASCADE
);
