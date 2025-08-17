#!/usr/bin/env python3
"""
Skrip forensik untuk validasi mendalam terhadap potensi nonce reuse
pada transaksi Solana dari multiple exchange (Bybit, Jupiter, OKX).
Melakukan analisis komparatif antar exchange.
"""

import pandas as pd
import requests
import hashlib
import json
import sys
import numpy as np
from collections import Counter
from typing import Dict, List, Tuple, Optional
from scipy import stats
from datetime import datetime
import argparse

try:
    from config import HELIUS_API_KEY
except ImportError:
    print("ERROR: File config.py tidak ditemukan atau HELIUS_API_KEY tidak terdefinisi.")
    print("Buat file config.py dengan HELIUS_API_KEY = 'your_api_key_here'")
    sys.exit(1)

# Konstanta Ed25519
L = 2**252 + 27742317777372353535851937790883648493

def modInverse(a: int, m: int) -> int:
    """Menghitung modular multiplicative inverse menggunakan Extended Euclidean Algorithm."""
    if m == 1:
        return 0
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse tidak ada")
    return (x % m + m) % m

def perform_chi_squared_test(r_components: List[str]) -> Tuple[float, float, str, Dict]:
    """Melakukan uji Chi-Squared pada distribusi byte pertama dari komponen R."""
    print("🔬 Melakukan Uji Statistik Chi-Squared pada distribusi byte pertama...")
    
    first_bytes = []
    for r_comp in r_components:
        try:
            first_byte = int(r_comp[:2], 16)
            first_bytes.append(first_byte)
        except (ValueError, IndexError):
            continue
    
    if len(first_bytes) < 10:
        return 0.0, 1.0, "TIDAK_CUKUP_DATA", {}
    
    observed_freq = Counter(first_bytes)
    observed = np.zeros(256)
    for byte_val, count in observed_freq.items():
        observed[byte_val] = count
    
    total_samples = len(first_bytes)
    expected_freq = total_samples / 256
    expected = np.full(256, expected_freq)
    
    mask = expected >= 5
    observed_filtered = observed[mask]
    expected_filtered = expected[mask]
    
    if len(observed_filtered) < 2:
        return 0.0, 1.0, "TIDAK_VALID", {}
    
    chi2_stat, p_value = stats.chisquare(observed_filtered, expected_filtered)
    
    alpha = 0.05
    if p_value < alpha:
        interpretation = "NON_RANDOM"
        conclusion = "Distribusi menunjukkan pola non-random (kemungkinan kerentanan)"
    else:
        interpretation = "RANDOM"
        conclusion = "Distribusi tampak random (normal)"
    
    detailed_stats = {
        'total_samples': total_samples,
        'unique_values': len(observed_freq),
        'most_frequent_byte': max(observed_freq, key=observed_freq.get) if observed_freq else None,
        'max_frequency': max(observed_freq.values()) if observed_freq else 0,
        'conclusion': conclusion,
        'degrees_of_freedom': len(observed_filtered) - 1
    }
    
    print(f"✓ Chi-Squared Statistic: {chi2_stat:.6f}")
    print(f"✓ P-Value: {p_value:.6f}")
    print(f"✓ Interpretation: {conclusion}")
    
    return chi2_stat, p_value, interpretation, detailed_stats

def analyze_single_file(csv_file: str) -> Dict:
    """Menganalisis satu file CSV dan mengembalikan hasil analisis."""
    print(f"\n" + "=" * 100)
    print(f"🔍 MEMULAI ANALISIS: {csv_file}")
    print("=" * 100)
    
    try:
        df = pd.read_csv(csv_file)
        print(f"✅ Berhasil membaca file: {csv_file}")
        print(f"📊 Dimensi data: {df.shape[0]:,} baris × {df.shape[1]} kolom")
        print(f"💾 Ukuran memori: {df.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB")
        
    except FileNotFoundError:
        print(f"❌ File tidak ditemukan: {csv_file}")
        return None
    except Exception as e:
        print(f"❌ Error membaca file {csv_file}: {str(e)}")
        return None
    
    # Validasi kolom yang diperlukan
    required_columns = ['signature_hash', 'r_component_hex']
    optional_columns = ['message_hash_hex']
    
    missing_required = [col for col in required_columns if col not in df.columns]
    if missing_required:
        print(f"❌ ERROR: Kolom yang diperlukan tidak ditemukan: {missing_required}")
        print(f"   Kolom yang ada: {list(df.columns)}")
        return None
    
    has_message_hash = 'message_hash_hex' in df.columns
    print(f"📧 Message hash tersedia: {'YA' if has_message_hash else 'TIDAK'}")
    
    # Analisis duplikasi R components
    print(f"\n🔍 ANALISIS DUPLIKASI KOMPONEN R:")
    r_counts = df['r_component_hex'].value_counts()
    duplicate_r = r_counts[r_counts > 1]
    
    total_signatures = len(df)
    unique_r = df['r_component_hex'].nunique()
    duplicate_r_count = len(duplicate_r)
    duplicate_rate = (duplicate_r_count / unique_r * 100) if unique_r > 0 else 0
    
    print(f"   • Total signature: {total_signatures:,}")
    print(f"   • Unique R components: {unique_r:,}")
    print(f"   • Duplicate R components: {duplicate_r_count}")
    print(f"   • Tingkat duplikasi: {duplicate_rate:.4f}%")
    
    # Analisis message hash jika tersedia
    message_stats = {}
    if has_message_hash:
        print(f"\n📧 ANALISIS MESSAGE HASH:")
        message_counts = df['message_hash_hex'].value_counts()
        duplicate_messages = message_counts[message_counts > 1]
        
        unique_messages = df['message_hash_hex'].nunique()
        duplicate_message_count = len(duplicate_messages)
        message_duplicate_rate = (duplicate_message_count / unique_messages * 100) if unique_messages > 0 else 0
        
        print(f"   • Unique message hash: {unique_messages:,}")
        print(f"   • Duplicate message hash: {duplicate_message_count}")
        print(f"   • Tingkat duplikasi message: {message_duplicate_rate:.4f}%")
        
        message_stats = {
            'unique_messages': unique_messages,
            'duplicate_messages': duplicate_message_count,
            'message_duplicate_rate': message_duplicate_rate
        }
    
    # Uji Chi-Squared
    chi2_stat, p_value, interpretation, chi2_details = perform_chi_squared_test(df['r_component_hex'].tolist())
    
    # Analisis entropi
    print(f"\n🔍 ANALISIS ENTROPI:")
    combined_hex = ''.join(df['r_component_hex'].astype(str))
    char_counts = Counter(combined_hex)
    total_chars = len(combined_hex)
    
    entropy = 0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * np.log2(p)
    
    max_entropy = 4.0  # log2(16) untuk hex chars
    entropy_ratio = entropy / max_entropy if entropy > 0 else 0
    
    print(f"   • Shannon Entropy: {entropy:.4f} / {max_entropy:.4f}")
    print(f"   • Rasio Entropy: {entropy_ratio * 100:.2f}%")
    
    # Penilaian risiko
    risk_score = 0
    risk_factors = []
    
    if duplicate_r_count > 0:
        risk_score += 20
        risk_factors.append("Duplikasi komponen R ditemukan")
    
    if p_value < 0.05:
        risk_score += 30
        risk_factors.append("Distribusi non-random terdeteksi")
    
    if entropy_ratio < 0.95:
        risk_score += 25
        risk_factors.append("Entropi rendah")
    
    if duplicate_r_count > total_signatures * 0.01:  # > 1%
        risk_score += 25
        risk_factors.append("Tingkat duplikasi tinggi")
    
    # Tentukan level risiko
    if risk_score >= 70:
        risk_level = "🔴 TINGGI"
    elif risk_score >= 40:
        risk_level = "🟡 SEDANG"
    else:
        risk_level = "🟢 RENDAH"
    
    print(f"\n⚠️  PENILAIAN TINGKAT RISIKO:")
    print(f"   • Level Risiko: {risk_level} (Skor: {risk_score}/100)")
    if risk_factors:
        print(f"   • Faktor Risiko:")
        for factor in risk_factors:
            print(f"     - {factor}")
    
    return {
        'file_name': csv_file,
        'total_signatures': total_signatures,
        'unique_r': unique_r,
        'duplicate_r': duplicate_r_count,
        'duplicate_rate': duplicate_rate,
        'chi2_stat': chi2_stat,
        'p_value': p_value,
        'interpretation': interpretation,
        'entropy': entropy,
        'entropy_ratio': entropy_ratio,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_factors': risk_factors,
        'has_message_hash': has_message_hash,
        'message_stats': message_stats
    }

def generate_comparative_report(results: List[Dict]):
    """Menghasilkan laporan perbandingan antar exchange."""
    print(f"\n" + "=" * 100)
    print("📊 LAPORAN PERBANDINGAN ANTAR EXCHANGE")
    print("=" * 100)
    print(f"🕒 Timestamp Analisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Tabel perbandingan
    print(f"\n📋 RINGKASAN PERBANDINGAN:")
    print("-" * 100)
    print(f"{'Exchange':<15} {'Total Sig':<12} {'Unique R':<12} {'Dup R':<8} {'Dup Rate':<12} {'Risk Level':<15}")
    print("-" * 100)
    
    for result in results:
        if result:
            exchange = result['file_name'].replace('nonce_forensic_log_100k_', '').replace('.csv', '').upper()
            print(f"{exchange:<15} {result['total_signatures']:<12,} {result['unique_r']:<12,} "
                  f"{result['duplicate_r']:<8} {result['duplicate_rate']:<12.4f}% {result['risk_level']:<15}")
    
    print("-" * 100)
    
    # Analisis statistik perbandingan
    print(f"\n🔬 ANALISIS STATISTIK PERBANDINGAN:")
    valid_results = [r for r in results if r]
    
    if len(valid_results) > 1:
        # Perbandingan tingkat duplikasi
        dup_rates = [r['duplicate_rate'] for r in valid_results]
        print(f"   • Rata-rata tingkat duplikasi: {np.mean(dup_rates):.4f}%")
        print(f"   • Standar deviasi duplikasi: {np.std(dup_rates):.4f}%")
        print(f"   • Range duplikasi: {min(dup_rates):.4f}% - {max(dup_rates):.4f}%")
        
        # Perbandingan entropi
        entropies = [r['entropy_ratio'] for r in valid_results]
        print(f"   • Rata-rata rasio entropi: {np.mean(entropies)*100:.2f}%")
        print(f"   • Standar deviasi entropi: {np.std(entropies)*100:.2f}%")
        
        # Perbandingan p-value
        p_values = [r['p_value'] for r in valid_results]
        print(f"   • Rata-rata p-value Chi-Squared: {np.mean(p_values):.6f}")
        
        # Exchange dengan risiko tertinggi dan terendah
        # Gunakan kombinasi risk_score dan duplicate_rate sebagai metrik
        highest_risk = max(valid_results, key=lambda x: (x['risk_score'], x['duplicate_rate']))
        lowest_risk = min(valid_results, key=lambda x: (x['risk_score'], x['duplicate_rate']))
        
        print(f"\n🎯 TEMUAN UTAMA:")
        
        # Cek apakah semua exchange memiliki risk score yang sama
        risk_scores = [r['risk_score'] for r in valid_results]
        if len(set(risk_scores)) == 1:
            # Jika semua risk score sama, gunakan duplicate rate sebagai pembeda
            highest_dup = max(valid_results, key=lambda x: x['duplicate_rate'])
            lowest_dup = min(valid_results, key=lambda x: x['duplicate_rate'])
            
            print(f"   • Semua exchange memiliki risk score yang sama: {risk_scores[0]}/100")
            print(f"   • Exchange dengan duplikasi tertinggi: {highest_dup['file_name']} ({highest_dup['duplicate_rate']:.4f}%)")
            print(f"   • Exchange dengan duplikasi terendah: {lowest_dup['file_name']} ({lowest_dup['duplicate_rate']:.4f}%)")
        else:
            print(f"   • Exchange dengan risiko tertinggi: {highest_risk['file_name']} (Skor: {highest_risk['risk_score']})")
            print(f"   • Exchange dengan risiko terendah: {lowest_risk['file_name']} (Skor: {lowest_risk['risk_score']})")
        
        # Rekomendasi
        print(f"\n📝 REKOMENDASI:")
        high_risk_exchanges = [r for r in valid_results if r['risk_score'] >= 40]
        if high_risk_exchanges:
            print(f"   🚨 PERHATIAN KHUSUS:")
            for exchange in high_risk_exchanges:
                print(f"     • {exchange['file_name']}: Monitoring intensif diperlukan")
        else:
            print(f"   ✅ SEMUA EXCHANGE: Dalam batas normal, lanjutkan monitoring rutin")

def main():
    """Fungsi utama untuk menjalankan analisis multi-exchange."""
    print("🔍 NONCE REUSE FORENSIC ANALYZER - MULTI EXCHANGE")
    print("=" * 60)
    print("Menganalisis potensi nonce reuse pada transaksi Solana")
    print("dari multiple exchange: Bybit, Jupiter, OKX")
    print("=" * 60)
    
    # Daftar file yang akan dianalisis
    csv_files = [
        "nonce_forensic_log_100k_bybit.csv",
        "nonce_forensic_log_100k_jup.csv", 
        "nonce_forensic_log_100k_okx.csv"
    ]
    
    results = []
    
    # Analisis setiap file
    for csv_file in csv_files:
        result = analyze_single_file(csv_file)
        results.append(result)
    
    # Generate laporan perbandingan
    generate_comparative_report(results)
    
    print(f"\n" + "=" * 100)
    print("🏁 ANALISIS MULTI-EXCHANGE SELESAI")
    print("=" * 100)
    print("💾 Simpan output ini sebagai bagian dari laporan audit forensik.")

if __name__ == "__main__":
    main()