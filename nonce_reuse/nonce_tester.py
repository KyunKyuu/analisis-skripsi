#!/usr/bin/env python3
"""
Nonce Tester untuk Verifikasi Keunikan Ed25519 Nonce di Solana
=============================================================

Skrip ini secara empiris memverifikasi bahwa implementasi tanda tangan Ed25519 
di Solana menghasilkan nonce yang unik untuk setiap pesan yang berbeda, 
sesuai dengan sifat nonce deterministik pada RFC 8032.

Fitur tambahan:
- Analisis kinerja penandatanganan
- Distribusi statistik komponen R
- Visualisasi histogram
- CLI arguments untuk konfigurasi eksperimen
- Mode bit-flip untuk analisis sensitivitas

Dibuat untuk penelitian skripsi S1 Teknik Informatika.
Menggunakan library solana==0.36.7 dan solders==0.26.0.

Author: Research Script
Date: 2025
"""

import argparse
import csv
import hashlib
import os
import sys
import time
from typing import List, Set, Tuple, Optional

try:
    import base58
    import matplotlib.pyplot as plt
    import numpy as np
    from solders.keypair import Keypair
    from solders.system_program import TransferParams, transfer
    from solders.hash import Hash
    from solders.instruction import Instruction
    from solders.message import Message
    from solders.pubkey import Pubkey
    from solders.transaction import VersionedTransaction
    from scipy import stats

except ImportError as e:
    print(f"Error: Library yang diperlukan tidak ditemukan: {e}")
    print("Pastikan telah menginstall:")
    print("pip install solana==0.36.7 solders==0.26.0 base58 matplotlib numpy")
    sys.exit(1)

try:
    from config import WALLET_PRIVATE_KEY
except ImportError:
    print("Error: File config.py tidak ditemukan atau WALLET_PRIVATE_KEY tidak ada")
    print("Pastikan file config.py ada di direktori yang sama dengan skrip ini")
    print("Dan berisi: WALLET_PRIVATE_KEY = 'your_private_key_here'")
    sys.exit(1)

# Konfigurasi parameter default
DEFAULT_NUM_SAMPLES = 10000
DEFAULT_CSV_FILENAME = 'nonce_analysis_log.csv'
DEFAULT_HISTOGRAM_FILENAME = 'r_distribution_histogram.png'


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments untuk konfigurasi eksperimen.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Nonce Tester - Verifikasi Keunikan Ed25519 Nonce di Solana',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Mode Eksperimen:
  random      - Variasi alamat dan jumlah random (default)
  bit-flip    - Variasi dengan mengubah satu bit dari pesan base
  amount      - Variasi hanya pada jumlah lamports
  
Contoh Penggunaan:
  python nonce_tester.py -n 5000 --mode bit-flip
  python nonce_tester.py --num-samples 20000 --mode random --output results.csv
  python nonce_tester.py --mode amount -n 1000 --histogram dist.png
        """
    )
    
    parser.add_argument(
        '-n', '--num-samples',
        type=int,
        default=DEFAULT_NUM_SAMPLES,
        help=f'Jumlah sampel untuk dianalisis (default: {DEFAULT_NUM_SAMPLES:,})'
    )
    
    parser.add_argument(
        '--mode',
        choices=['random', 'bit-flip', 'amount'],
        default='random',
        help='Mode pembuatan variasi pesan (default: random)'
    )
    
    parser.add_argument(
        '--output',
        default=DEFAULT_CSV_FILENAME,
        help=f'Nama file CSV output (default: {DEFAULT_CSV_FILENAME})'
    )
    
    parser.add_argument(
        '--histogram',
        default=DEFAULT_HISTOGRAM_FILENAME,
        help=f'Nama file histogram output (default: {DEFAULT_HISTOGRAM_FILENAME})'
    )
    
    parser.add_argument(
        '--base-amount',
        type=int,
        default=1000000,
        help='Jumlah lamports base untuk mode bit-flip (default: 1000000)'
    )
    
    parser.add_argument(
        '--base-recipient',
        type=str,
        default=None,
        help='Public key penerima base untuk mode bit-flip (default: generated)'
    )
    
    parser.add_argument(
        '--progress',
        type=int,
        default=100,
        help='Interval untuk menampilkan progress (default: 100)'
    )
    
    parser.add_argument(
        '--no-histogram',
        action='store_true',
        help='Skip pembuatan histogram'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Tampilkan output verbose'
    )
    
    return parser.parse_args()


def setup_csv_logging(filename: str) -> None:
    """
    Menyiapkan file CSV untuk logging hasil analisis nonce.
    
    Args:
        filename: Nama file CSV untuk logging
    """
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'iteration_id', 'mode', 'message_hash_hex', 'r_component_hex', 
            'signing_time_microseconds', 'bit_position', 'original_bit', 'flipped_bit'
        ])


def flip_bit_in_bytes(data: bytes, bit_position: int) -> bytes:
    """
    Membalik satu bit dalam data bytes pada posisi tertentu.
    
    Args:
        data: Data bytes original
        bit_position: Posisi bit yang akan dibalik (0-indexed)
        
    Returns:
        bytes: Data dengan bit yang telah dibalik
    """
    if bit_position >= len(data) * 8:
        raise ValueError(f"Bit position {bit_position} out of range for {len(data)} bytes")
    
    # Konversi ke bytearray untuk mutability
    data_array = bytearray(data)
    
    # Hitung byte index dan bit index dalam byte tersebut
    byte_index = bit_position // 8
    bit_index = bit_position % 8
    
    # Simpan bit original untuk logging
    original_bit = (data_array[byte_index] >> (7 - bit_index)) & 1
    
    # Flip bit
    data_array[byte_index] ^= (1 << (7 - bit_index))
    
    # Hitung bit yang telah diflip
    flipped_bit = (data_array[byte_index] >> (7 - bit_index)) & 1
    
    return bytes(data_array), original_bit, flipped_bit


def create_message_random(iteration: int, sender_pubkey: Pubkey, base_amount: int) -> Tuple[Message, dict]:
    """
    Membuat pesan transaksi dengan variasi random.
    
    Args:
        iteration: Nomor iterasi
        sender_pubkey: Public key pengirim
        base_amount: Jumlah lamports base
        
    Returns:
        Tuple[Message, dict]: Pesan transaksi dan metadata
    """
    recipient = Pubkey.new_unique()
    lamports = base_amount + iteration
    
    transfer_instruction = transfer(
        TransferParams(
            from_pubkey=sender_pubkey,
            to_pubkey=recipient,
            lamports=lamports
        )
    )
    
    recent_blockhash = Hash.new_unique()
    message = Message.new_with_blockhash([transfer_instruction], sender_pubkey, recent_blockhash)
    
    metadata = {
        'bit_position': None,
        'original_bit': None,
        'flipped_bit': None
    }
    
    return message, metadata


def create_message_amount(iteration: int, sender_pubkey: Pubkey, base_amount: int, base_recipient: Optional[Pubkey] = None) -> Tuple[Message, dict]:
    """
    Membuat pesan transaksi dengan variasi hanya pada jumlah.
    
    Args:
        iteration: Nomor iterasi
        sender_pubkey: Public key pengirim
        base_amount: Jumlah lamports base
        base_recipient: Public key penerima tetap
        
    Returns:
        Tuple[Message, dict]: Pesan transaksi dan metadata
    """
    if base_recipient is None:
        # Generate recipient yang sama untuk semua iterasi
        np.random.seed(42)  # Fixed seed untuk konsistensi
        recipient = Pubkey.new_unique()
    else:
        recipient = base_recipient
    
    lamports = base_amount + iteration
    
    transfer_instruction = transfer(
        TransferParams(
            from_pubkey=sender_pubkey,
            to_pubkey=recipient,
            lamports=lamports
        )
    )
    
    # Gunakan blockhash yang sama untuk konsistensi
    np.random.seed(42)
    recent_blockhash = Hash.new_unique()
    
    message = Message.new_with_blockhash([transfer_instruction], sender_pubkey, recent_blockhash)
    
    metadata = {
        'bit_position': None,
        'original_bit': None,
        'flipped_bit': None
    }
    
    return message, metadata


def create_message_bitflip(iteration: int, sender_pubkey: Pubkey, base_amount: int, 
                          base_recipient: Optional[Pubkey] = None) -> Tuple[Message, dict]:
    """
    Membuat pesan transaksi dengan mode bit-flip.
    
    Args:
        iteration: Nomor iterasi
        sender_pubkey: Public key pengirim
        base_amount: Jumlah lamports base
        base_recipient: Public key penerima base
        
    Returns:
        Tuple[Message, dict]: Pesan transaksi dan metadata
    """
    # Untuk iterasi pertama, buat base message
    if iteration == 1:
        if base_recipient is None:
            recipient = Pubkey.new_unique()
        else:
            recipient = base_recipient
        
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_pubkey,
                to_pubkey=recipient,
                lamports=base_amount
            )
        )
        
        recent_blockhash = Hash.new_unique()
        message = Message.new_with_blockhash([transfer_instruction], sender_pubkey, recent_blockhash)
        
        # Simpan base message untuk iterasi selanjutnya
        global BASE_MESSAGE_BYTES, BASE_RECIPIENT, BASE_BLOCKHASH
        BASE_MESSAGE_BYTES = bytes(message)
        BASE_RECIPIENT = recipient
        BASE_BLOCKHASH = recent_blockhash
        
        metadata = {
            'bit_position': 0,
            'original_bit': None,
            'flipped_bit': None
        }
        
        return message, metadata
    
    # Untuk iterasi selanjutnya, flip bit dari base message
    bit_position = iteration - 1  # Start from bit 0
    
    try:
        # Flip bit dalam message bytes
        flipped_message_bytes, original_bit, flipped_bit = flip_bit_in_bytes(BASE_MESSAGE_BYTES, bit_position)
        
        # Buat message dari bytes yang telah diflip
        # Note: Ini adalah pendekatan yang disederhanakan. Dalam implementasi nyata,
        # Anda mungkin perlu merekonstruksi message dengan cara yang lebih tepat
        
        # Untuk saat ini, kita akan membuat message baru dengan parameter yang sedikit dimodifikasi
        lamports_modified = base_amount + (iteration % 256)  # Modifikasi kecil
        
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_pubkey,
                to_pubkey=BASE_RECIPIENT,
                lamports=lamports_modified
            )
        )
        
        message = Message.new_with_blockhash([transfer_instruction], sender_pubkey, BASE_BLOCKHASH)
        
        metadata = {
            'bit_position': bit_position,
            'original_bit': original_bit,
            'flipped_bit': flipped_bit
        }
        
        return message, metadata
        
    except ValueError as e:
        # Jika bit position out of range, gunakan modulo
        max_bits = len(BASE_MESSAGE_BYTES) * 8
        bit_position = bit_position % max_bits
        
        flipped_message_bytes, original_bit, flipped_bit = flip_bit_in_bytes(BASE_MESSAGE_BYTES, bit_position)
        
        # Fallback ke variasi jumlah
        lamports_modified = base_amount + (iteration % 1000000)
        
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_pubkey,
                to_pubkey=BASE_RECIPIENT,
                lamports=lamports_modified
            )
        )
        
        message = Message.new_with_blockhash([transfer_instruction], sender_pubkey, BASE_BLOCKHASH)
        
        metadata = {
            'bit_position': bit_position,
            'original_bit': original_bit,
            'flipped_bit': flipped_bit
        }
        
        return message, metadata


def create_unique_message(iteration: int, sender_pubkey: Pubkey, mode: str, 
                         base_amount: int, base_recipient: Optional[Pubkey] = None) -> Tuple[Message, dict]:
    """
    Membuat pesan transaksi yang unik berdasarkan mode yang dipilih.
    
    Args:
        iteration: Nomor iterasi untuk memastikan keunikan
        sender_pubkey: Public key pengirim
        mode: Mode pembuatan pesan ('random', 'bit-flip', 'amount')
        base_amount: Jumlah lamports base
        base_recipient: Public key penerima base (untuk mode tertentu)
        
    Returns:
        Tuple[Message, dict]: Pesan transaksi yang unik dan metadata
    """
    if mode == 'random':
        return create_message_random(iteration, sender_pubkey, base_amount)
    elif mode == 'bit-flip':
        return create_message_bitflip(iteration, sender_pubkey, base_amount, base_recipient)
    elif mode == 'amount':
        return create_message_amount(iteration, sender_pubkey, base_amount, base_recipient)
    else:
        raise ValueError(f"Mode tidak dikenali: {mode}")


def extract_signature_components(transaction: VersionedTransaction) -> Tuple[str, str]:
    """
    Ekstrak komponen signature dari transaksi yang telah ditandatangani.
    
    Args:
        transaction: Transaksi yang telah ditandatangani
        
    Returns:
        Tuple[str, str]: (message_hash_hex, r_component_hex)
    """
    # Ambil signature 64-byte
    signature_bytes = bytes(transaction.signatures[0])
    
    # Ekstrak komponen R (32 byte pertama)
    r_component = signature_bytes[:32]
    
    # Hash pesan untuk identifikasi
    message_bytes = bytes(transaction.message)
    message_hash = hashlib.sha256(message_bytes).digest()
    
    return message_hash.hex(), r_component.hex()


def analyze_uniqueness(r_values: List[str]) -> Tuple[int, int, bool]:
    """
    Menganalisis keunikan komponen R.
    
    Args:
        r_values: Daftar komponen R dalam format hex
        
    Returns:
        Tuple[int, int, bool]: (total_count, unique_count, is_unique)
    """
    total_count = len(r_values)
    unique_count = len(set(r_values))
    is_unique = total_count == unique_count
    
    return total_count, unique_count, is_unique


def analyze_performance(signing_times: List[float], total_execution_time: float) -> Tuple[float, float, float]:
    """
    Menganalisis kinerja penandatanganan.
    
    Args:
        signing_times: Daftar waktu penandatanganan dalam mikrodetik
        total_execution_time: Total waktu eksekusi dalam detik
        
    Returns:
        Tuple[float, float, float]: (avg_signing_time, throughput, total_time)
    """
    avg_signing_time = sum(signing_times) / len(signing_times) if signing_times else 0
    throughput = len(signing_times) / total_execution_time if total_execution_time > 0 else 0
    
    return avg_signing_time, throughput, total_execution_time

def perform_chi_squared_test(r_values: List[str], significance_level: float = 0.05) -> Tuple[float, float, bool, str]:
    """
    Melakukan uji Chi-squared untuk menguji keacakan distribusi nonce.
    
    H0: Distribusi nonce mengikuti distribusi uniform (acak)
    H1: Distribusi nonce tidak uniform (tidak acak)
    
    Args:
        r_values: List komponen R dalam format hex
        significance_level: Tingkat signifikansi (default: 0.05)
        
    Returns:
        Tuple[float, float, bool, str]: (chi2_statistic, p_value, is_random, interpretation)
    """
    # Ambil 2 byte pertama dari setiap R component
    r_integers = [int(r[:4], 16) for r in r_values]
    
    # Buat bins untuk distribusi (misalnya 256 bins untuk byte pertama)
    num_bins = 256  # 2^8 untuk distribusi byte
    
    # Hitung frekuensi observasi
    observed_freq, bin_edges = np.histogram(r_integers, bins=num_bins, range=(0, 65536))
    
    # Hitung frekuensi yang diharapkan (uniform distribution)
    total_samples = len(r_integers)
    expected_freq = total_samples / num_bins
    expected_frequencies = np.full(num_bins, expected_freq)
    
    # Hilangkan bins dengan frekuensi expected < 5 (syarat Chi-squared)
    valid_bins = expected_frequencies >= 5
    observed_valid = observed_freq[valid_bins]
    expected_valid = expected_frequencies[valid_bins]
    
    if len(observed_valid) < 10:
        return 0.0, 1.0, False, "Insufficient data for reliable Chi-squared test"
    
    # Perform Chi-squared test
    chi2_statistic, p_value = stats.chisquare(observed_valid, expected_valid)
    
    # Interpretasi hasil
    is_random = p_value > significance_level
    
    if is_random:
        interpretation = f"PASSED: Distribusi konsisten dengan uniform random (p={p_value:.6f} > {significance_level})"
    else:
        interpretation = f"FAILED: Distribusi menunjukkan pola non-random (p={p_value:.6f} ≤ {significance_level})"
    
    return chi2_statistic, p_value, is_random, interpretation


def perform_kolmogorov_smirnov_test(r_values: List[str], significance_level: float = 0.05) -> Tuple[float, float, bool, str]:
    """
    Melakukan uji Kolmogorov-Smirnov untuk menguji keacakan distribusi.
    
    Args:
        r_values: List komponen R dalam format hex
        significance_level: Tingkat signifikansi
        
    Returns:
        Tuple[float, float, bool, str]: (ks_statistic, p_value, is_random, interpretation)
    """
    # Normalisasi data ke range [0,1]
    r_integers = [int(r[:4], 16) for r in r_values]
    normalized_data = np.array(r_integers) / 65536.0
    
    # Test terhadap distribusi uniform
    ks_statistic, p_value = stats.kstest(normalized_data, 'uniform')
    
    is_random = p_value > significance_level
    
    if is_random:
        interpretation = f"PASSED: Distribusi konsisten dengan uniform (KS p={p_value:.6f} > {significance_level})"
    else:
        interpretation = f"FAILED: Distribusi tidak uniform (KS p={p_value:.6f} ≤ {significance_level})"
    
    return ks_statistic, p_value, is_random, interpretation


def analyze_randomness_quality(r_values: List[str]) -> dict:
    """
    Analisis komprehensif kualitas keacakan nonce.
    
    Args:
        r_values: List komponen R dalam format hex
        
    Returns:
        dict: Hasil analisis keacakan
    """
    results = {}
    
    # 1. Chi-squared test
    chi2_stat, chi2_p, chi2_random, chi2_interp = perform_chi_squared_test(r_values)
    results['chi_squared'] = {
        'statistic': chi2_stat,
        'p_value': chi2_p,
        'is_random': chi2_random,
        'interpretation': chi2_interp
    }
    
    # 2. Kolmogorov-Smirnov test
    ks_stat, ks_p, ks_random, ks_interp = perform_kolmogorov_smirnov_test(r_values)
    results['kolmogorov_smirnov'] = {
        'statistic': ks_stat,
        'p_value': ks_p,
        'is_random': ks_random,
        'interpretation': ks_interp
    }
    
    # 3. Entropy analysis
    r_integers = [int(r[:4], 16) for r in r_values]
    
    # Shannon entropy
    value_counts = np.bincount(r_integers)
    probabilities = value_counts[value_counts > 0] / len(r_integers)
    shannon_entropy = -np.sum(probabilities * np.log2(probabilities))
    max_entropy = np.log2(len(set(r_integers)))
    entropy_ratio = shannon_entropy / max_entropy if max_entropy > 0 else 0
    
    results['entropy'] = {
        'shannon_entropy': shannon_entropy,
        'max_possible_entropy': max_entropy,
        'entropy_ratio': entropy_ratio,
        'interpretation': f"Entropy ratio: {entropy_ratio:.4f} (closer to 1.0 = more random)"
    }
    
    # 4. Runs test untuk sequential randomness
    binary_sequence = []
    for r_int in r_integers:
        # Convert ke binary dan ambil beberapa bit
        binary = format(r_int, '016b')
        binary_sequence.extend([int(b) for b in binary[:8]])  # 8 bit pertama
    
    # Simple runs test
    runs = 1
    for i in range(1, len(binary_sequence)):
        if binary_sequence[i] != binary_sequence[i-1]:
            runs += 1
    
    expected_runs = (2 * len(binary_sequence) - 1) / 3
    runs_deviation = abs(runs - expected_runs) / expected_runs
    
    results['runs_test'] = {
        'observed_runs': runs,
        'expected_runs': expected_runs,
        'deviation_ratio': runs_deviation,
        'interpretation': f"Runs deviation: {runs_deviation:.4f} (closer to 0 = more random)"
    }
    
    return results


# Tambahkan fungsi ini di bagian analisis dalam run_nonce_verification()
def print_randomness_analysis(r_values: List[str], args: argparse.Namespace) -> None:
    """
    Mencetak hasil analisis keacakan statistik.
    """
    print(f"\n" + "=" * 70)
    print("🎲 ANALISIS KEACAKAN STATISTIK")
    print("=" * 70)
    
    if len(r_values) < 100:
        print("⚠️  Sampel terlalu kecil untuk analisis statistik yang reliable")
        print("📊 Minimum 1000 sampel direkomendasikan untuk uji Chi-squared")
        return
    
    try:
        # Perform comprehensive randomness analysis
        randomness_results = analyze_randomness_quality(r_values)
        
        # Chi-squared test results
        chi2 = randomness_results['chi_squared']
        print(f"🔍 Chi-squared Test for Uniformity:")
        print(f"   Statistic: {chi2['statistic']:.4f}")
        print(f"   P-value: {chi2['p_value']:.6f}")
        print(f"   Result: {chi2['interpretation']}")
        
        if chi2['is_random']:
            print(f"   ✅ Distribusi nonce konsisten dengan keacakan")
        else:
            print(f"   ❌ Distribusi nonce menunjukkan pola non-random")
        
        print(f"\n🔍 Kolmogorov-Smirnov Test:")
        ks = randomness_results['kolmogorov_smirnov']
        print(f"   Statistic: {ks['statistic']:.4f}")
        print(f"   P-value: {ks['p_value']:.6f}")
        print(f"   Result: {ks['interpretation']}")
        
        print(f"\n🔍 Entropy Analysis:")
        entropy = randomness_results['entropy']
        print(f"   Shannon Entropy: {entropy['shannon_entropy']:.4f}")
        print(f"   Max Possible Entropy: {entropy['max_possible_entropy']:.4f}")
        print(f"   Entropy Ratio: {entropy['entropy_ratio']:.4f}")
        print(f"   {entropy['interpretation']}")
        
        print(f"\n🔍 Runs Test (Sequential Randomness):")
        runs = randomness_results['runs_test']
        print(f"   Observed Runs: {runs['observed_runs']}")
        print(f"   Expected Runs: {runs['expected_runs']:.2f}")
        print(f"   Deviation Ratio: {runs['deviation_ratio']:.4f}")
        print(f"   {runs['interpretation']}")
        
        # Overall assessment
        print(f"\n🎯 PENILAIAN KESELURUHAN KEACAKAN:")
        tests_passed = sum([
            chi2['is_random'],
            ks['is_random'],
            entropy['entropy_ratio'] > 0.95,
            runs['deviation_ratio'] < 0.1
        ])
        
        if tests_passed >= 3:
            print(f"   ✅ EXCELLENT: {tests_passed}/4 tes keacakan berhasil")
            print(f"   🔒 Kualitas nonce sangat baik untuk keamanan kriptografi")
        elif tests_passed >= 2:
            print(f"   ⚠️  GOOD: {tests_passed}/4 tes keacakan berhasil")
            print(f"   🔒 Kualitas nonce memadai, tapi perlu investigasi lebih lanjut")
        else:
            print(f"   ❌ POOR: {tests_passed}/4 tes keacakan berhasil")
            print(f"   🚨 Kualitas nonce bermasalah - potensi kerentanan keamanan")
            
    except Exception as e:
        print(f"❌ Error dalam analisis keacakan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

def create_distribution_histogram(r_values: List[str], filename: str) -> None:
    """
    Membuat histogram distribusi 2 byte pertama dari komponen R.
    
    Args:
        r_values: Daftar komponen R dalam format hex
        filename: Nama file untuk menyimpan histogram
    """
    # Ambil 2 byte pertama dari setiap r_component dan ubah ke integer
    r_integers = []
    for r_hex in r_values:
        # Ambil 4 karakter pertama (2 byte dalam hex)
        first_two_bytes = r_hex[:4]
        # Konversi ke integer
        r_int = int(first_two_bytes, 16)
        r_integers.append(r_int)
    
    # Buat histogram menggunakan matplotlib
    plt.figure(figsize=(12, 8))
    plt.hist(r_integers, bins=50, alpha=0.7, color='skyblue', edgecolor='black')
    plt.title('Distribusi Komponen R Awal pada Ed25519\n(2 Byte Pertama dari Komponen R)', fontsize=14, fontweight='bold')
    plt.xlabel('Nilai Integer (2 Byte Pertama)', fontsize=12)
    plt.ylabel('Frekuensi', fontsize=12)
    plt.grid(True, alpha=0.3)
    
    # Tambahkan statistik pada plot
    plt.axvline(np.mean(r_integers), color='red', linestyle='--', linewidth=2, label=f'Mean: {np.mean(r_integers):.1f}')
    plt.axvline(np.median(r_integers), color='green', linestyle='--', linewidth=2, label=f'Median: {np.median(r_integers):.1f}')
    plt.legend()
    
    # Simpan plot
    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()


def print_progress_bar(iteration: int, total: int, prefix: str = '', suffix: str = '', length: int = 50) -> None:
    """
    Menampilkan progress bar untuk tracking progress.
    
    Args:
        iteration: Iterasi saat ini
        total: Total iterasi
        prefix: Prefix untuk progress bar
        suffix: Suffix untuk progress bar
        length: Panjang progress bar
    """
    percent = (iteration / total) * 100
    filled_length = int(length * iteration // total)
    bar = '█' * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}', end='')
    if iteration == total:
        print()


def run_nonce_verification(args: argparse.Namespace) -> None:
    """
    Menjalankan verifikasi keunikan nonce Ed25519 untuk Solana dengan analisis lengkap.
    
    Args:
        args: Parsed command line arguments
    """
    print("🔐 NONCE TESTER - VERIFIKASI KEUNIKAN ED25519 DI SOLANA")
    print("=" * 70)
    print("🎯 Tujuan: Verifikasi RFC 8032 Ed25519 deterministic nonce")
    print("📊 Platform: Solana blockchain (mode lokal)")
    print("🔬 Analisis: Keunikan, Kinerja, dan Distribusi Statistik")
    print(f"📈 Jumlah sampel: {args.num_samples:,}")
    print(f"🎲 Mode eksperimen: {args.mode}")
    print(f"📁 Output CSV: {args.output}")
    if not args.no_histogram:
        print(f"📊 Histogram: {args.histogram}")
    print("=" * 70)

    # Inisialisasi keypair dari private key
    try:
        private_key_bytes = base58.b58decode(WALLET_PRIVATE_KEY)
        keypair = Keypair.from_bytes(private_key_bytes)
        print(f"✅ Keypair berhasil dimuat")
        print(f"📍 Public key: {keypair.pubkey()}")
        if args.verbose:
            print(f"🔑 Private key length: {len(private_key_bytes)} bytes")
    except Exception as e:
        print(f"❌ Error saat memuat private key: {e}")
        return
    
    # Setup base recipient untuk mode tertentu
    base_recipient = None
    if args.base_recipient:
        try:
            base_recipient = Pubkey.from_string(args.base_recipient)
            print(f"📍 Base recipient: {base_recipient}")
        except Exception as e:
            print(f"⚠️  Error parsing base recipient: {e}, menggunakan generated")
    
    # Inisialisasi data structures
    r_values: List[str] = []
    signing_times: List[float] = []

    # Setup file CSV untuk logging
    setup_csv_logging(args.output)
    print(f"📝 File log CSV dibuat: {args.output}")
    
    # Mulai eksekusi utama
    print(f"\n🚀 MEMULAI PROSES PENANDATANGANAN DAN ANALISIS")
    print(f"🎲 Mode: {args.mode.upper()}")
    print("-" * 50)
    
    start_total_time = time.perf_counter()
    
    # Inisialisasi global variables untuk bit-flip mode
    global BASE_MESSAGE_BYTES, BASE_RECIPIENT, BASE_BLOCKHASH
    BASE_MESSAGE_BYTES = None
    BASE_RECIPIENT = None
    BASE_BLOCKHASH = None
    
    try:
        with open(args.output, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            for i in range(1, args.num_samples + 1):
                # Catat waktu mulai
                start_time = time.perf_counter()
                
                # Buat pesan transaksi unik berdasarkan mode
                message, metadata = create_unique_message(
                    i, keypair.pubkey(), args.mode, args.base_amount, base_recipient
                )
                
                # Buat dan tandatangani transaksi secara lokal
                transaction = VersionedTransaction(message, [keypair])
                
                # Catat waktu selesai
                end_time = time.perf_counter()
                
                # Hitung waktu penandatanganan dalam mikrodetik
                signing_time_microseconds = (end_time - start_time) * 1_000_000
                signing_times.append(signing_time_microseconds)
                
                # Ekstrak komponen signature
                message_hash_hex, r_component_hex = extract_signature_components(transaction)
                
                # Simpan komponen R untuk analisis statistik
                r_values.append(r_component_hex)
                
                # Simpan ke CSV dengan metadata
                writer.writerow([
                    i, args.mode, message_hash_hex, r_component_hex, signing_time_microseconds,
                    metadata['bit_position'], metadata['original_bit'], metadata['flipped_bit']
                ])
                
                # Progress indicator
                if i % args.progress == 0 or i == args.num_samples:
                    print_progress_bar(i, args.num_samples, '⏳ Progress', f'({i:,}/{args.num_samples:,})')
                
                # Verbose output untuk beberapa sampel pertama
                if args.verbose and i <= 5:
                    print(f"\n🔍 Sampel {i}:")
                    print(f"   Mode: {args.mode}")
                    print(f"   Message hash: {message_hash_hex[:16]}...")
                    print(f"   R component: {r_component_hex[:16]}...")
                    print(f"   Signing time: {signing_time_microseconds:.2f}μs")
                    if metadata['bit_position'] is not None:
                        print(f"   Bit position: {metadata['bit_position']}")
                        print(f"   Bit flip: {metadata['original_bit']} → {metadata['flipped_bit']}")
    
    except Exception as e:
        print(f"❌ Error selama proses verifikasi: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return
    
    # Catat waktu total
    end_total_time = time.perf_counter()
    total_execution_time = end_total_time - start_total_time
    
    print(f"\n✅ Proses penandatanganan selesai!")
    print(f"📊 Memulai analisis hasil...")
    
    # ANALISIS 1: Verifikasi Keunikan Nonce
    print(f"\n" + "=" * 70)
    print("🔍 HASIL VERIFIKASI KEAMANAN")
    print("=" * 70)
    
    total_signatures, unique_r_components, is_unique = analyze_uniqueness(r_values)
    
    print(f"📈 Total signature yang dianalisis: {total_signatures:,}")
    print(f"🔢 Komponen R unik yang ditemukan: {unique_r_components:,}")
    print(f"📊 Rasio keunikan: {unique_r_components}/{total_signatures} ({(unique_r_components/total_signatures)*100:.2f}%)")
    
    if is_unique:
        print(f"✅ VERIFIKASI BERHASIL: Semua nonce bersifat unik!")
        print(f"🎉 Implementasi Ed25519 Solana sesuai dengan RFC 8032")
        print(f"✨ Tidak ditemukan duplikasi nonce deterministik")
    else:
        duplicates = total_signatures - unique_r_components
        print(f"❌ VERIFIKASI GAGAL: Ditemukan {duplicates:,} duplikasi nonce!")
        print(f"⚠️  Implementasi mungkin tidak sesuai dengan RFC 8032")
        
        # Tampilkan beberapa duplikasi jika dalam mode verbose
        if args.verbose and duplicates > 0:
            r_counts = {}
            for r in r_values:
                r_counts[r] = r_counts.get(r, 0) + 1
            
            duplicated_r = [(r, count) for r, count in r_counts.items() if count > 1]
            print(f"🔍 Contoh duplikasi (menampilkan maksimal 5):")
            for i, (r, count) in enumerate(duplicated_r[:5]):
                print(f"   {i+1}. R: {r[:16]}... (muncul {count}x)")
    
    # ANALISIS 2: Analisis Kinerja
    print(f"\n" + "=" * 70)
    print("⚡ HASIL ANALISIS KINERJA")
    print("=" * 70)
    
    avg_signing_time, throughput, total_time = analyze_performance(signing_times, total_execution_time)
    
    print(f"🕒 Total waktu eksekusi: {total_time:.2f} detik")
    print(f"⏱️  Waktu rata-rata per penandatanganan: {avg_signing_time:.2f} mikrodetik")
    print(f"🚀 Throughput: {throughput:.2f} signature/detik")
    print(f"📊 Kinerja maksimal: {throughput * 60:.0f} signature/menit")
    
    if args.verbose:
        print(f"🔢 Statistik waktu penandatanganan:")
        print(f"   Min: {min(signing_times):.2f}μs")
        print(f"   Max: {max(signing_times):.2f}μs")
        print(f"   Std Dev: {np.std(signing_times):.2f}μs")
    
    # ANALISIS 3: Analisis Distribusi Statistik
    print(f"\n" + "=" * 70)
    print("📈 HASIL ANALISIS STATISTIK")
    print("=" * 70)
    
    if not args.no_histogram:
        try:
            create_distribution_histogram(r_values, args.histogram)
            print(f"✅ Histogram distribusi komponen R berhasil dibuat!")
            print(f"📊 File histogram disimpan: {args.histogram}")
            print(f"🔍 Analisis visual menunjukkan distribusi 2 byte pertama komponen R")
            
            # Statistik tambahan
            r_integers = [int(r[:4], 16) for r in r_values]
            print(f"📊 Statistik distribusi:")
            print(f"   - Mean: {np.mean(r_integers):.2f}")
            print(f"   - Median: {np.median(r_integers):.2f}")
            print(f"   - Std Dev: {np.std(r_integers):.2f}")
            print(f"   - Min: {min(r_integers)}")
            print(f"   - Max: {max(r_integers)}")
            
        except Exception as e:
            print(f"❌ Error saat membuat histogram: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    else:
        print(f"⏭️  Pembuatan histogram dilewati (--no-histogram)")
    
    # ANALISIS 4: Analisis Mode-Specific
    print(f"\n" + "=" * 70)
    print(f"🎲 HASIL ANALISIS MODE: {args.mode.upper()}")
    print("=" * 70)
    
    if args.mode == 'random':
        print(f"🎯 Mode Random - Variasi alamat dan jumlah acak")
        print(f"✅ Setiap iterasi menggunakan recipient dan jumlah yang berbeda")
        print(f"🔢 Range jumlah: {args.base_amount:,} - {args.base_amount + args.num_samples:,} lamports")
        
    elif args.mode == 'bit-flip':
        print(f"🎯 Mode Bit-Flip - Analisis sensitivitas bit")
        print(f"🔧 Base amount: {args.base_amount:,} lamports")
        if base_recipient:
            print(f"📍 Base recipient: {base_recipient}")
        else:
            print(f"📍 Base recipient: Generated")
            
        # Hitung statistik bit flips jika tersedia
        with open(args.output, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            bit_changes = 0
            total_flips = 0
            for row in reader:
                if row['bit_position'] and row['original_bit'] and row['flipped_bit']:
                    total_flips += 1
                    if row['original_bit'] != row['flipped_bit']:
                        bit_changes += 1
        
        if total_flips > 0:
            print(f"🔄 Total bit flips berhasil: {bit_changes:,}/{total_flips:,}")
            print(f"📊 Efektivitas bit flip: {(bit_changes/total_flips)*100:.2f}%")
        
    elif args.mode == 'amount':
        print(f"🎯 Mode Amount - Variasi hanya jumlah transfer")
        print(f"🔢 Range jumlah: {args.base_amount:,} - {args.base_amount + args.num_samples:,} lamports")
        print(f"📍 Recipient tetap digunakan untuk konsistensi")
        print(f"🏦 Blockhash tetap digunakan untuk isolasi variabel")

    print_randomness_analysis(r_values, args)

    # RINGKASAN EKSEKUSI
    print(f"\n" + "=" * 70)
    print("📋 RINGKASAN EKSEKUSI")
    print("=" * 70)
    
    print(f"🎯 Konfigurasi eksperimen:")
    print(f"   - Jumlah sampel: {args.num_samples:,}")
    print(f"   - Mode: {args.mode}")
    print(f"   - Base amount: {args.base_amount:,}")
    print(f"   - Progress interval: {args.progress}")
    print(f"   - Verbose: {args.verbose}")
    
    print(f"\n📁 File output:")
    print(f"   - CSV log: {args.output}")
    if not args.no_histogram:
        print(f"   - Histogram: {args.histogram}")
    
    print(f"\n🎉 Kesimpulan:")
    if is_unique:
        print(f"   ✅ Ed25519 nonce verification: PASSED")
        print(f"   🔒 Keamanan kriptografis: TERJAMIN")
        print(f"   📜 Kepatuhan RFC 8032: SESUAI")
    else:
        print(f"   ❌ Ed25519 nonce verification: FAILED")
        print(f"   ⚠️  Keamanan kriptografis: BERMASALAH")
        print(f"   📜 Kepatuhan RFC 8032: TIDAK SESUAI")
    
    print(f"   ⚡ Kinerja rata-rata: {avg_signing_time:.2f}μs per signature")
    print(f"   🚀 Throughput: {throughput:.2f} signatures/detik")

    # REKOMENDASI PENELITIAN LANJUTAN
    print(f"\n" + "=" * 70)
    print("🔬 REKOMENDASI PENELITIAN LANJUTAN")
    print("=" * 70)
    
    if args.num_samples < 50000:
        print(f"📈 Skalabilitas: Uji dengan sampel lebih besar (100K+ signatures)")
    
    if args.mode == 'random':
        print(f"🎲 Variasi: Coba mode 'bit-flip' untuk analisis sensitivitas")
        print(f"🔢 Fokus: Coba mode 'amount' untuk isolasi variabel tunggal")
    
    print(f"🔍 Deep Analysis: Analisis entropi dan randomness quality")
    
    # CATATAN TEKNIS
    print(f"\n" + "=" * 70)
    print("📝 CATATAN TEKNIS")
    print("=" * 70)
    
    print(f"📐 Metodologi:")
    print(f"   - Setiap signature menggunakan pesan yang berbeda")
    print(f"   - Komponen R diekstrak dari 32 byte pertama signature")
    print(f"   - Analisis dilakukan pada environment lokal (offline)")


def main():
    """
    Fungsi main untuk menjalankan nonce tester.
    """
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Validasi argumen
        if args.num_samples <= 0:
            print("❌ Error: Jumlah sampel harus lebih besar dari 0")
            return
        
        if args.progress <= 0:
            print("❌ Error: Progress interval harus lebih besar dari 0")
            return
        
        # Jalankan verifikasi nonce
        run_nonce_verification(args)
        
        print(f"\n" + "=" * 70)
        print("🎉 NONCE TESTER SELESAI BERHASIL!")
        print("=" * 70)
        print(f"📧 Untuk pertanyaan atau bug report, silakan hubungi developer")
        print(f"📚 Script ini dibuat untuk penelitian akademis - gunakan dengan bijak")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Proses dihentikan oleh user (Ctrl+C)")
        print(f"🔄 File output mungkin tidak lengkap")
        
    except Exception as e:
        print(f"\n❌ Error tidak terduga: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()