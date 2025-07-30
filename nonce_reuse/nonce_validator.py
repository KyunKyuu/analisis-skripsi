#!/usr/bin/env python3
"""
Skrip forensik untuk validasi mendalam terhadap potensi nonce reuse
pada transaksi Solana. Melakukan identifikasi duplikat, verifikasi
kondisi kerentanan, uji statistik Chi-Squared, dan demonstrasi 
implikasi kriptografis.

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
    """
    Menghitung modular multiplicative inverse menggunakan Extended Euclidean Algorithm.
    
    Args:
        a (int): Bilangan yang akan dicari inversnya
        m (int): Modulus
    
    Returns:
        int: Modular multiplicative inverse dari a mod m
    """
    if m == 1:
        return 0
    
    # Extended Euclidean Algorithm
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
    """
    Melakukan uji Chi-Squared pada distribusi byte pertama dari komponen R.
    
    Args:
        r_components (List[str]): List komponen R dalam format hex
    
    Returns:
        Tuple[float, float, str, Dict]: (chi2_stat, p_value, interpretation, detailed_stats)
    """
    print("🔬 Melakukan Uji Statistik Chi-Squared pada distribusi byte pertama...")
    
    # Ekstrak byte pertama dari setiap komponen R
    first_bytes = []
    for r_comp in r_components:
        try:
            # Ambil 2 karakter pertama (1 byte dalam hex)
            first_byte = int(r_comp[:2], 16)
            first_bytes.append(first_byte)
        except (ValueError, IndexError):
            continue
    
    if len(first_bytes) < 10:
        return 0.0, 1.0, "TIDAK_CUKUP_DATA", {}
    
    # Hitung frekuensi aktual
    observed_freq = Counter(first_bytes)
    
    # Buat array frekuensi untuk semua kemungkinan nilai byte (0-255)
    observed = np.zeros(256)
    for byte_val, count in observed_freq.items():
        observed[byte_val] = count
    
    # Frekuensi yang diharapkan untuk distribusi uniform
    total_samples = len(first_bytes)
    expected_freq = total_samples / 256
    expected = np.full(256, expected_freq)
    
    # Hanya gunakan nilai yang memiliki frekuensi expected >= 5 untuk validitas Chi-Squared
    mask = expected >= 5
    observed_filtered = observed[mask]
    expected_filtered = expected[mask]
    
    if len(observed_filtered) < 2:
        return 0.0, 1.0, "TIDAK_VALID", {}
    
    # Lakukan uji Chi-Squared
    chi2_stat, p_value = stats.chisquare(observed_filtered, expected_filtered)
    
    # Interpretasi hasil
    alpha = 0.05
    if p_value < alpha:
        interpretation = "NON_RANDOM"
        conclusion = "Distribusi menunjukkan pola non-random (kemungkinan kerentanan)"
    else:
        interpretation = "RANDOM"
        conclusion = "Distribusi tampak random (normal)"
    
    # Statistik detail
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

def analyze_randomness_patterns(r_components: List[str]) -> Dict:
    """
    Menganalisis pola-pola dalam komponen R yang bisa mengindikasikan kelemahan RNG.
    
    Args:
        r_components (List[str]): List komponen R dalam format hex
    
    Returns:
        Dict: Hasil analisis pola
    """
    print("🔍 Menganalisis pola keacakan dalam komponen R...")
    
    patterns = {
        'sequential_patterns': 0,
        'repeated_prefixes': {},
        'entropy_analysis': {},
        'bit_bias': {}
    }
    
    # Analisis prefix yang berulang
    prefixes = {}
    for r_comp in r_components:
        prefix = r_comp[:8]  # 4 bytes pertama
        prefixes[prefix] = prefixes.get(prefix, 0) + 1
    
    # Cari prefix yang muncul lebih dari sekali
    repeated_prefixes = {k: v for k, v in prefixes.items() if v > 1}
    patterns['repeated_prefixes'] = repeated_prefixes
    
    # Analisis entropi sederhana
    if r_components:
        combined_hex = ''.join(r_components)
        char_counts = Counter(combined_hex)
        total_chars = len(combined_hex)
        
        # Hitung entropi Shannon
        entropy = 0
        for count in char_counts.values():
            p = count / total_chars
            if p > 0:
                entropy -= p * np.log2(p)
        
        patterns['entropy_analysis'] = {
            'shannon_entropy': entropy,
            'max_possible_entropy': 4.0,  # log2(16) untuk hex chars
            'entropy_ratio': entropy / 4.0 if entropy > 0 else 0
        }
    
    print(f"✓ Ditemukan {len(repeated_prefixes)} prefix yang berulang")
    print(f"✓ Entropi Shannon: {patterns['entropy_analysis'].get('shannon_entropy', 0):.4f}")
    
    return patterns

def perform_kolmogorov_smirnov_test(r_values: List[str], significance_level: float = 0.05) -> Tuple[float, float, bool, str]:
    r_integers = [int(r[:4], 16) for r in r_values]
    normalized_data = np.array(r_integers) / 65536.0
    ks_statistic, p_value = stats.kstest(normalized_data, 'uniform')
    is_random = p_value > significance_level
    interpretation = (
        f"PASSED: Distribusi konsisten dengan uniform (p={p_value:.6f} > {significance_level})"
        if is_random else
        f"FAILED: Distribusi tidak uniform (p={p_value:.6f} ≤ {significance_level})"
    )
    return ks_statistic, p_value, is_random, interpretation


def analyze_randomness_quality(r_values: List[str]) -> dict:
    results = {}
    chi2_stat, chi2_p, chi2_random, chi2_interp = perform_chi_squared_test(r_values)
    results['chi_squared'] = {
        'statistic': chi2_stat,
        'p_value': chi2_p,
        'is_random': chi2_random == "RANDOM",
        'interpretation': chi2_interp.get('conclusion') if isinstance(chi2_interp, dict) else chi2_interp
    }

    ks_stat, ks_p, ks_random, ks_interp = perform_kolmogorov_smirnov_test(r_values)
    results['kolmogorov_smirnov'] = {
        'statistic': ks_stat,
        'p_value': ks_p,
        'is_random': ks_random,
        'interpretation': ks_interp
    }

    r_integers = [int(r[:4], 16) for r in r_values]
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

    binary_sequence = []
    for r_int in r_integers:
        binary = format(r_int, '016b')
        binary_sequence.extend([int(b) for b in binary[:8]])
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


def print_randomness_analysis(r_values: List[str], args: argparse.Namespace = argparse.Namespace(verbose=False)) -> None:
    print(f"\n" + "=" * 70)
    print("🎲 ANALISIS KEACAKAN STATISTIK")
    print("=" * 70)
    if len(r_values) < 100:
        print("⚠️  Sampel terlalu kecil untuk analisis statistik yang reliable")
        return
    try:
        randomness_results = analyze_randomness_quality(r_values)
        chi2 = randomness_results['chi_squared']
        print(f"🔍 Chi-squared Test: {chi2['interpretation']}")

        ks = randomness_results['kolmogorov_smirnov']
        print(f"🔍 KS Test: {ks['interpretation']}")

        entropy = randomness_results['entropy']
        print(f"🔍 Entropy: {entropy['interpretation']}")

        runs = randomness_results['runs_test']
        print(f"🔍 Runs Test: {runs['interpretation']}")

        tests_passed = sum([
            chi2['is_random'],
            ks['is_random'],
            entropy['entropy_ratio'] > 0.95,
            runs['deviation_ratio'] < 0.1
        ])

        print(f"\n🎯 KESELURUHAN: {tests_passed}/4 Tes Randomness Lulus")
    except Exception as e:
        print(f"❌ Error dalam analisis keacakan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def fetch_transaction_details(signature: str) -> Optional[Dict]:
    url = f"https://rpc.helius.xyz"
    params = {"api-key": HELIUS_API_KEY}
    
    # Payload untuk RPC call
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "json",
                "maxSupportedTransactionVersion": 0
            }
        ]
    }
    
    try:
        response = requests.post(url, json=payload, params=params, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        
        if "error" in result:
            print(f"  ERROR: RPC error untuk {signature[:8]}...: {result['error']}")
            return None
            
        if "result" not in result or result["result"] is None:
            print(f"  ERROR: Transaksi tidak ditemukan: {signature[:8]}...")
            return None
            
        return result["result"]
    except requests.exceptions.RequestException as e:
        print(f"  ERROR: Gagal mengambil transaksi {signature[:8]}...: {e}")
        return None

def extract_message_hash(transaction_data: Dict) -> Optional[str]:
    """
    Mengekstrak dan menghash pesan dari data transaksi Solana.
    
    Args:
        transaction_data (Dict): Data transaksi dari RPC API
    
    Returns:
        Optional[str]: Hash pesan dalam format hex atau None jika gagal
    """
    try:
        # Ekstrak transaction dari result
        transaction = transaction_data.get('transaction', {})
        
        # Ambil message dari transaction
        message = transaction.get('message', {})
        
        # Untuk Solana, kita bisa menggunakan beberapa pendekatan:
        # 1. Hash dari serialized message
        # 2. Hash dari instructions
        # 3. Hash dari accounts dan data
        
        # Method 1: Hash dari serialized message
        if message:
            # Serialisasi message ke JSON string kemudian ke bytes
            message_str = json.dumps(message, sort_keys=True)
            message_bytes = message_str.encode('utf-8')
            
            # Hitung SHA256 hash
            hash_digest = hashlib.sha256(message_bytes).hexdigest()
            
            return hash_digest
        
        # Method 2: Fallback - hash dari instructions jika message tidak ada
        instructions = message.get('instructions', [])
        if instructions:
            instructions_str = json.dumps(instructions, sort_keys=True)
            instructions_bytes = instructions_str.encode('utf-8')
            hash_digest = hashlib.sha256(instructions_bytes).hexdigest()
            return hash_digest
            
        return None
        
    except Exception as e:
        print(f"  ERROR: Gagal mengekstrak hash pesan: {e}")
        return None

def extract_s_component(signature: str) -> Optional[int]:
    """
    Mengekstrak komponen S dari signature Ed25519.
    
    Args:
        signature (str): Signature dalam format hex (64 bytes)
    
    Returns:
        Optional[int]: Komponen S sebagai integer atau None jika gagal
    """
    try:
        # Signature Ed25519 adalah 64 bytes: 32 bytes R + 32 bytes S
        signature_bytes = bytes.fromhex(signature)
        
        if len(signature_bytes) != 64:
            print(f"  ERROR: Signature harus 64 bytes, ditemukan {len(signature_bytes)} bytes")
            return None
        
        # Ekstrak 32 bytes terakhir (komponen S)
        s_bytes = signature_bytes[32:]
        
        # Konversi ke integer (little-endian untuk Ed25519)
        s_int = int.from_bytes(s_bytes, byteorder='little')
        
        return s_int
    except Exception as e:
        print(f"  ERROR: Gagal mengekstrak komponen S: {e}")
        return None

def generate_detailed_report(df: pd.DataFrame, duplicate_groups: pd.DataFrame, 
                           chi2_result: Tuple, patterns: Dict, vulnerability_found: bool) -> None:
    """
    Menghasilkan laporan forensik yang komprehensif.
    """
    print("\n" + "=" * 80)
    print("📋 LAPORAN FORENSIK KOMPREHENSIF")
    print("=" * 80)
    print(f"🕒 Timestamp Analisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Statistik Dasar
    print("📊 STATISTIK DASAR:")
    print(f"   • Total Signature Dianalisis: {len(df):,}")
    print(f"   • Unique R Components: {df['r_component_hex'].nunique():,}")
    print(f"   • Duplicate R Components: {duplicate_groups['r_component_hex'].nunique() if not duplicate_groups.empty else 0}")
    print(f"   • Tingkat Duplikasi: {(duplicate_groups['r_component_hex'].nunique() / df['r_component_hex'].nunique() * 100):.2f}%" if not duplicate_groups.empty and df['r_component_hex'].nunique() > 0 else "   • Tingkat Duplikasi: 0.00%")
    print()
    
    # Hasil Uji Chi-Squared
    chi2_stat, p_value, interpretation, detailed_stats = chi2_result
    print("🧮 HASIL UJI STATISTIK CHI-SQUARED:")
    print(f"   • Chi-Squared Statistic: {chi2_stat:.6f}")
    print(f"   • P-Value: {p_value:.6f}")
    print(f"   • Degrees of Freedom: {detailed_stats.get('degrees_of_freedom', 'N/A')}")
    print(f"   • Total Samples: {detailed_stats.get('total_samples', 'N/A'):,}")
    print(f"   • Unique Values: {detailed_stats.get('unique_values', 'N/A')}")
    print(f"   • Interpretasi: {detailed_stats.get('conclusion', 'N/A')}")
    
    # Signifikansi statistik
    if p_value < 0.001:
        significance = "SANGAT SIGNIFIKAN (p < 0.001)"
    elif p_value < 0.01:
        significance = "SIGNIFIKAN (p < 0.01)"
    elif p_value < 0.05:
        significance = "MODERATE SIGNIFIKAN (p < 0.05)"
    else:
        significance = "TIDAK SIGNIFIKAN (p ≥ 0.05)"
    
    print(f"   • Signifikansi Statistik: {significance}")
    print()
    
    # Analisis Pola Keacakan
    print("🔍 ANALISIS POLA KEACAKAN:")
    entropy_info = patterns.get('entropy_analysis', {})
    print(f"   • Shannon Entropy: {entropy_info.get('shannon_entropy', 0):.4f} / 4.0000")
    print(f"   • Rasio Entropy: {entropy_info.get('entropy_ratio', 0):.2%}")
    
    repeated_prefixes = patterns.get('repeated_prefixes', {})
    if repeated_prefixes:
        print(f"   • Prefix Berulang: {len(repeated_prefixes)} ditemukan")
        for prefix, count in sorted(repeated_prefixes.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"     - {prefix}: {count} kali")
    else:
        print("   • Prefix Berulang: Tidak ditemukan")
    print()
    
    # Tingkat Risiko
    print("⚠️  PENILAIAN TINGKAT RISIKO:")
    
    risk_factors = []
    risk_score = 0
    
    if vulnerability_found:
        risk_factors.append("Kerentanan nonce reuse aktif terdeteksi")
        risk_score += 40
    
    if duplicate_groups['r_component_hex'].nunique() > 0:
        risk_factors.append("Duplikasi komponen R ditemukan")
        risk_score += 20
    
    if interpretation == "NON_RANDOM":
        risk_factors.append("Distribusi menunjukkan pola non-random")
        risk_score += 25
    
    if entropy_info.get('entropy_ratio', 1.0) < 0.9:
        risk_factors.append("Entropi di bawah threshold normal")
        risk_score += 15
    
    # Tentukan level risiko
    if risk_score >= 70:
        risk_level = "🔴 KRITIKAL"
        risk_color = "MERAH"
    elif risk_score >= 50:
        risk_level = "🟡 TINGGI"
        risk_color = "KUNING"
    elif risk_score >= 30:
        risk_level = "🟠 SEDANG"
        risk_color = "ORANGE"
    else:
        risk_level = "🟢 RENDAH"
        risk_color = "HIJAU"
    
    print(f"   • Level Risiko: {risk_level} (Skor: {risk_score}/100)")
    print("   • Faktor Risiko:")
    if risk_factors:
        for factor in risk_factors:
            print(f"     - {factor}")
    else:
        print("     - Tidak ada faktor risiko signifikan terdeteksi")
    print()
    
    # Rekomendasi
    print("📝 REKOMENDASI TINDAK LANJUT:")
    if risk_score >= 50:
        print("   🚨 TINDAKAN SEGERA DIPERLUKAN:")
        print("     • Hentikan sementara sistem yang terpengaruh")
        print("     • Lakukan rotasi kunci segera")
        print("     • Audit mendalam pada sistem signature")
        print("     • Implementasi monitoring nonce real-time")
    elif risk_score >= 30:
        print("   ⚠️  TINDAKAN PENCEGAHAN DIREKOMENDASIKAN:")
        print("     • Monitor sistem secara ketat")
        print("     • Evaluasi implementasi RNG")
        print("     • Pertimbangkan rotasi kunci preventif")
    else:
        print("   ✅ TINDAKAN RUTIN:")
        print("     • Lanjutkan monitoring berkala")
        print("     • Dokumentasikan hasil analisis")
    
    print()
    print("=" * 80)
    print("🔍 Analisis forensik selesai.")
    print("💾 Untuk dokumentasi lebih lanjut, simpan output ini sebagai bagian dari laporan audit.")

def analyze_nonce_reuse():
    """
    Fungsi utama untuk menganalisis nonce reuse dari file CSV dengan analisis statistik lengkap.
    """
    print("=" * 80)
    print("NONCE REUSE VALIDATOR - FORENSIK BLOCKCHAIN (ENHANCED)")
    print("=" * 80)
    print("Version: 2.0 - Dengan Uji Statistik Chi-Squared")
    print()
    
    # Langkah 1: Baca CSV dan temukan duplikat R
    print("🔍 LANGKAH 1: Membaca file CSV dan mencari duplikat komponen R...")
    
    try:
        df = pd.read_csv('nonce_forensic_log_jup.csv')
        print(f"✓ Berhasil membaca {len(df):,} record dari nonce_forensic_log.csv")
    except FileNotFoundError:
        print("❌ ERROR: File nonce_forensic_log.csv tidak ditemukan!")
        print("💡 Mencoba file alternatif: nonce_forensic_log_jup.csv")
        try:
            df = pd.read_csv('nonce_forensic_log_jup.csv')
            print(f"✓ Berhasil membaca {len(df):,} record dari nonce_forensic_log_jup.csv")
        except FileNotFoundError:
            print("❌ ERROR: File nonce_forensic_log_jup.csv juga tidak ditemukan!")
            return
    except Exception as e:
        print(f"❌ ERROR: Gagal membaca file CSV: {e}")
        return
    
    # Validasi kolom yang diperlukan
    required_columns = ['signature_hash', 'r_component_hex']
    if not all(col in df.columns for col in required_columns):
        print(f"❌ ERROR: Kolom yang diperlukan tidak ditemukan: {required_columns}")
        print(f"   Kolom yang ada: {list(df.columns)}")
        return
    
    print()
    print("=" * 80)
    print("📊 LANGKAH 2: Analisis Statistik dan Pola Keacakan")
    print("=" * 80)
    
    # Lakukan uji Chi-Squared pada semua komponen R
    r_components = df['r_component_hex'].tolist()
    chi2_result = perform_chi_squared_test(r_components)
    
    # Analisis pola keacakan
    patterns = analyze_randomness_patterns(r_components)
    print_randomness_analysis(r_components)

    
    # Kelompokkan berdasarkan r_component_hex untuk mencari duplikat
    duplicate_groups = df.groupby('r_component_hex').filter(lambda x: len(x) > 1)
    
    print()
    print("=" * 80)
    print("🔬 LANGKAH 3: Analisis Duplikasi dan Kerentanan Nonce Reuse")
    print("=" * 80)
    
    if duplicate_groups.empty:
        print("✅ Tidak ditemukan duplikasi nonce.")
        vulnerability_found = False
    else:
        # Hitung jumlah komponen R yang duplikat
        duplicate_r_count = duplicate_groups['r_component_hex'].nunique()
        print(f"🚨 Ditemukan {duplicate_r_count} komponen R duplikat. Memulai analisis mendalam...")
        print()
        
        # Tampilkan ringkasan duplikat
        for r_component, group in duplicate_groups.groupby('r_component_hex'):
            signatures = group['signature_hash'].tolist()
            print(f"📋 R Component: {r_component}")
            for i, sig in enumerate(signatures, 1):
                print(f"   {i}. {sig}")
            print()
        
        print("🔄 Mengambil detail transaksi untuk verifikasi pesan...")
        
        # Analisis setiap kelompok duplikat
        vulnerability_found = False
        
        for r_component, group in duplicate_groups.groupby('r_component_hex'):
            signatures = group['signature_hash'].tolist()
            
            print(f"--- Menganalisis Duplikasi untuk R: {r_component} ---")
            
            # Ambil detail untuk setiap signature
            transaction_details = []
            for sig in signatures:
                print(f"🔄 Mengambil detail transaksi: {sig[:16]}...")
                details = fetch_transaction_details(sig)
                if details:
                    transaction_details.append((sig, details))
                    print(f"✓ Berhasil")
                else:
                    print(f"❌ Gagal")
            
            # Bandingkan setiap pasang transaksi
            for i in range(len(transaction_details)):
                for j in range(i + 1, len(transaction_details)):
                    sig1, details1 = transaction_details[i]
                    sig2, details2 = transaction_details[j]
                    
                    print(f"\n> Signature 1: {sig1}")
                    print(f"> Signature 2: {sig2}")
                    
                    # Ekstrak hash pesan
                    hash1 = extract_message_hash(details1)
                    hash2 = extract_message_hash(details2)
                    
                    if hash1 and hash2:
                        print(f"  - Hash Pesan 1: {hash1}")
                        print(f"  - Hash Pesan 2: {hash2}")
                        
                        messages_different = hash1 != hash2
                        print(f"  - Apakah Pesan Berbeda? {messages_different}")
                        
                        if messages_different:
                            vulnerability_found = True
                            
                            # Ekstrak komponen S
                            s1 = extract_s_component(sig1)
                            s2 = extract_s_component(sig2)
                            
                            if s1 and s2:
                                print(f"  - Nilai S1 (int): {s1}")
                                print(f"  - Nilai S2 (int): {s2}")
                                
                                # Langkah 4: Tampilkan rumus dan pembuktian teoretis
                                print("\n" + "=" * 60)
                                print("🔐 DEMONSTRASI PEMULIHAN KUNCI PRIVAT (TEORETIS)")
                                print("=" * 60)
                                
                                print("\n📐 RUMUS MATEMATIS:")
                                print("   k = (hash(m1) - hash(m2)) * modInverse(s1 - s2, L) mod L")
                                print("   sk = modInverse(r, L) * (k*s1 - hash(m1)) mod L")
                                
                                print("\n📊 VARIABEL YANG DIKETAHUI:")
                                print(f"   - hash(m1) = 0x{hash1}")
                                print(f"   - hash(m2) = 0x{hash2}")
                                print(f"   - s1 = {s1}")
                                print(f"   - s2 = {s2}")
                                print(f"   - r = 0x{r_component}")
                                print(f"   - L = {L} (konstanta orde Ed25519)")
                                
                                print("\n🔒 KESIMPULAN:")
                                print("   Dengan variabel di atas, kunci privat secara teoretis dapat dihitung.")
                                print("   KONDISI KERENTANAN NONCE REUSE TERKONFIRMASI!")
                            else:
                                print("  ❌ Gagal mengekstrak komponen S dari signature")
                        else:
                            print("  ✅ Pesan identik - tidak ada kerentanan nonce reuse")
                    else:
                        print("  ❌ Gagal mengekstrak hash pesan")
                    
                    print("-" * 60)
    
    # Generate laporan komprehensif
    generate_detailed_report(df, duplicate_groups, chi2_result, patterns, vulnerability_found)

if __name__ == "__main__":
    analyze_nonce_reuse()