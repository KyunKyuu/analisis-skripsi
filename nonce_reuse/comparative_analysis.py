#!/usr/bin/env python3
"""
Script untuk menghasilkan analisis komparatif antara data primer (eksperimental)
dan data sekunder (real-world) dengan metrik pengujian yang konsisten.
"""

import csv
import math
from collections import Counter
from datetime import datetime
import json

def perform_chi_squared_test(r_components):
    """Uji Chi-Squared pada distribusi byte pertama komponen R"""
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
    total_samples = len(first_bytes)
    expected_freq = total_samples / 256
    
    # Hitung Chi-Squared statistic secara manual
    chi2_stat = 0.0
    valid_categories = 0
    
    for byte_val in range(256):
        observed = observed_freq.get(byte_val, 0)
        expected = expected_freq
        
        if expected >= 5:  # Kriteria minimum untuk validitas
            chi2_stat += ((observed - expected) ** 2) / expected
            valid_categories += 1
    
    if valid_categories < 2:
        return 0.0, 1.0, "TIDAK_VALID", {}
    
    # Estimasi p-value sederhana berdasarkan chi2_stat
    degrees_of_freedom = valid_categories - 1
    
    # Approximation untuk p-value (simplified)
    if chi2_stat < degrees_of_freedom * 0.5:
        p_value = 0.9
    elif chi2_stat < degrees_of_freedom * 1.0:
        p_value = 0.7
    elif chi2_stat < degrees_of_freedom * 1.5:
        p_value = 0.5
    elif chi2_stat < degrees_of_freedom * 2.0:
        p_value = 0.3
    elif chi2_stat < degrees_of_freedom * 3.0:
        p_value = 0.1
    else:
        p_value = 0.01
    
    interpretation = "RANDOM" if p_value >= 0.05 else "NON_RANDOM"
    
    detailed_stats = {
        'total_samples': total_samples,
        'unique_values': len(observed_freq),
        'degrees_of_freedom': degrees_of_freedom
    }
    
    return chi2_stat, p_value, interpretation, detailed_stats

def calculate_entropy(r_components):
    """Menghitung Shannon Entropy"""
    combined_hex = ''.join(r_components)
    char_counts = Counter(combined_hex)
    total_chars = len(combined_hex)
    
    entropy = 0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * math.log2(p)
    
    max_entropy = 4.0  # log2(16) untuk hex chars
    entropy_ratio = entropy / max_entropy if entropy > 0 else 0
    
    return entropy, entropy_ratio

def analyze_patterns(r_components):
    """Analisis pola dalam komponen R"""
    prefixes = {}
    for r_comp in r_components:
        prefix = r_comp[:8]  # 4 bytes pertama
        prefixes[prefix] = prefixes.get(prefix, 0) + 1
    
    repeated_prefixes = {k: v for k, v in prefixes.items() if v > 1}
    return repeated_prefixes

def calculate_risk_score(duplicate_count, total_unique, p_value, entropy_ratio, repeated_prefixes):
    """Menghitung skor risiko berdasarkan berbagai faktor"""
    risk_score = 0
    risk_factors = []
    
    # Faktor duplikasi
    if duplicate_count > 0:
        risk_score += 20
        risk_factors.append("Duplikasi komponen R ditemukan")
    
    # Faktor distribusi non-random
    if p_value < 0.05:
        risk_score += 30
        risk_factors.append("Distribusi non-random terdeteksi")
    
    # Faktor entropi rendah
    if entropy_ratio < 0.95:
        risk_score += 25
        risk_factors.append("Entropi rendah")
    
    # Faktor tingkat duplikasi tinggi
    duplicate_rate = (duplicate_count / total_unique * 100) if total_unique > 0 else 0
    if duplicate_rate > 1.0:  # > 1%
        risk_score += 25
        risk_factors.append("Tingkat duplikasi tinggi")
    
    # Faktor pola berulang
    if len(repeated_prefixes) > 5:
        risk_score += 10
        risk_factors.append("Banyak pola berulang")
    
    # Tentukan level risiko
    if risk_score >= 70:
        risk_level = "KRITIKAL"
    elif risk_score >= 50:
        risk_level = "TINGGI"
    elif risk_score >= 30:
        risk_level = "SEDANG"
    else:
        risk_level = "RENDAH"
    
    return risk_score, risk_level, risk_factors

def analyze_dataset(csv_file, dataset_type):
    """Menganalisis dataset dengan metrik yang konsisten"""
    print(f"\n🔍 MENGANALISIS {dataset_type.upper()}: {csv_file}")
    print("=" * 60)
    
    try:
        # Baca CSV
        data = []
        with open(csv_file, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            headers = csv_reader.fieldnames
            for row in csv_reader:
                data.append(row)
        
        print(f"✓ File berhasil dibaca: {len(data):,} baris")
        print(f"✓ Kolom tersedia: {headers}")
        
        # Tentukan kolom R component
        r_column = None
        for col in ['r_component_hex', 'r_component']:
            if col in headers:
                r_column = col
                break
        
        if r_column is None:
            print("❌ Kolom R component tidak ditemukan")
            return None
        
        # Ekstrak komponen R
        r_components = [row[r_column] for row in data if row[r_column]]
        
        # Analisis duplikasi
        r_counts = Counter(r_components)
        duplicate_r = {k: v for k, v in r_counts.items() if v > 1}
        
        total_signatures = len(data)
        unique_r = len(set(r_components))
        duplicate_r_count = len(duplicate_r)
        duplicate_rate = (duplicate_r_count / unique_r * 100) if unique_r > 0 else 0
        
        # Distribusi duplikasi
        duplicate_distribution = {}
        for count in duplicate_r.values():
            duplicate_distribution[count] = duplicate_distribution.get(count, 0) + 1
        
        # Uji Chi-Squared
        chi2_stat, p_value, interpretation, chi2_details = perform_chi_squared_test(r_components)
        
        # Analisis entropi
        entropy, entropy_ratio = calculate_entropy(r_components)
        
        # Analisis pola
        repeated_prefixes = analyze_patterns(r_components)
        
        # Analisis message hash (jika tersedia)
        message_stats = {}
        has_message_hash = 'message_hash_hex' in headers
        if has_message_hash:
            message_hashes = [row['message_hash_hex'] for row in data if row['message_hash_hex']]
            message_counts = Counter(message_hashes)
            duplicate_messages = {k: v for k, v in message_counts.items() if v > 1}
            
            unique_messages = len(set(message_hashes))
            duplicate_message_count = len(duplicate_messages)
            message_duplicate_rate = (duplicate_message_count / unique_messages * 100) if unique_messages > 0 else 0
            
            message_stats = {
                'unique_messages': unique_messages,
                'duplicate_messages': duplicate_message_count,
                'message_duplicate_rate': message_duplicate_rate
            }
        
        # Hitung skor risiko
        risk_score, risk_level, risk_factors = calculate_risk_score(
            duplicate_r_count, unique_r, p_value, entropy_ratio, repeated_prefixes
        )
        
        # Kompilasi hasil
        results = {
            'dataset_type': dataset_type,
            'file_name': csv_file,
            'total_signatures': total_signatures,
            'unique_r': unique_r,
            'duplicate_r': duplicate_r_count,
            'duplicate_rate': duplicate_rate,
            'duplicate_distribution': duplicate_distribution,
            'chi2_stat': chi2_stat,
            'p_value': p_value,
            'chi2_interpretation': interpretation,
            'degrees_of_freedom': chi2_details.get('degrees_of_freedom', 0),
            'entropy': entropy,
            'entropy_ratio': entropy_ratio,
            'repeated_prefixes_count': len(repeated_prefixes),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'has_message_hash': has_message_hash,
            'message_stats': message_stats
        }
        
        # Tampilkan hasil
        print(f"\n📊 HASIL ANALISIS {dataset_type.upper()}:")
        print(f"   • Total Signature: {total_signatures:,}")
        print(f"   • Unique R Components: {unique_r:,}")
        print(f"   • Duplicate R Components: {duplicate_r_count}")
        print(f"   • Tingkat Duplikasi: {duplicate_rate:.4f}%")
        print(f"   • Chi-Squared P-Value: {p_value:.6f}")
        print(f"   • Interpretasi: {interpretation}")
        print(f"   • Shannon Entropy: {entropy:.4f}")
        print(f"   • Entropy Ratio: {entropy_ratio:.2%}")
        print(f"   • Repeated Prefixes: {len(repeated_prefixes)}")
        print(f"   • Risk Score: {risk_score}/100")
        print(f"   • Risk Level: {risk_level}")
        
        if has_message_hash:
            print(f"   • Message Hash Analysis: Available")
            print(f"     - Unique Messages: {message_stats['unique_messages']:,}")
            print(f"     - Duplicate Messages: {message_stats['duplicate_messages']}")
            print(f"     - Message Duplicate Rate: {message_stats['message_duplicate_rate']:.4f}%")
        
        return results
        
    except Exception as e:
        print(f"❌ Error menganalisis {csv_file}: {e}")
        return None

def generate_comparative_table(primary_results, secondary_results):
    """Menghasilkan tabel perbandingan metrik"""
    print(f"\n" + "=" * 100)
    print("📋 TABEL PERBANDINGAN METRIK PENGUJIAN")
    print("=" * 100)
    
    # Header tabel
    print(f"{'METRIK':<35} {'DATA PRIMER':<25} {'DATA SEKUNDER':<25} {'SELISIH':<15}")
    print("-" * 100)
    
    # Metrik-metrik yang dibandingkan
    metrics = [
        ('Total Signatures', 'total_signatures', ','),
        ('Unique R Components', 'unique_r', ','),
        ('Duplicate R Components', 'duplicate_r', ''),
        ('Tingkat Duplikasi (%)', 'duplicate_rate', '.4f'),
        ('Chi-Squared Statistic', 'chi2_stat', '.6f'),
        ('P-Value', 'p_value', '.6f'),
        ('Shannon Entropy', 'entropy', '.4f'),
        ('Entropy Ratio (%)', 'entropy_ratio', '.2%'),
        ('Repeated Prefixes', 'repeated_prefixes_count', ''),
        ('Risk Score', 'risk_score', ''),
    ]
    
    for metric_name, metric_key, format_spec in metrics:
        primary_val = primary_results.get(metric_key, 0)
        secondary_val = secondary_results.get(metric_key, 0)
        
        # Format nilai
        if format_spec == ',':
            primary_str = f"{primary_val:,}"
            secondary_str = f"{secondary_val:,}"
            diff_str = f"{primary_val - secondary_val:+,}"
        elif format_spec == '.4f':
            primary_str = f"{primary_val:.4f}"
            secondary_str = f"{secondary_val:.4f}"
            diff_str = f"{primary_val - secondary_val:+.4f}"
        elif format_spec == '.6f':
            primary_str = f"{primary_val:.6f}"
            secondary_str = f"{secondary_val:.6f}"
            diff_str = f"{primary_val - secondary_val:+.6f}"
        elif format_spec == '.2%':
            primary_str = f"{primary_val:.2%}"
            secondary_str = f"{secondary_val:.2%}"
            diff_str = f"{primary_val - secondary_val:+.2%}"
        else:
            primary_str = str(primary_val)
            secondary_str = str(secondary_val)
            diff_str = f"{primary_val - secondary_val:+}"
        
        print(f"{metric_name:<35} {primary_str:<25} {secondary_str:<25} {diff_str:<15}")
    
    print("-" * 100)
    
    # Interpretasi kategorikal
    print(f"\n📊 PERBANDINGAN KATEGORIKAL:")
    print(f"   • Chi-Squared Interpretation:")
    print(f"     - Data Primer: {primary_results.get('chi2_interpretation', 'N/A')}")
    print(f"     - Data Sekunder: {secondary_results.get('chi2_interpretation', 'N/A')}")
    print(f"   • Risk Level:")
    print(f"     - Data Primer: {primary_results.get('risk_level', 'N/A')}")
    print(f"     - Data Sekunder: {secondary_results.get('risk_level', 'N/A')}")

def save_results_to_file(primary_results, secondary_results):
    """Menyimpan hasil ke file untuk dokumentasi skripsi"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"comparative_analysis_{timestamp}.txt"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("ANALISIS KOMPARATIF NONCE REUSE - DATA PRIMER VS SEKUNDER\n")
        f.write("=" * 100 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analyst: Forensic Blockchain Analyzer\n\n")
        
        # Ringkasan eksekutif
        f.write("RINGKASAN EKSEKUTIF\n")
        f.write("-" * 30 + "\n")
        f.write(f"Data Primer (Eksperimental): {primary_results['file_name']}\n")
        f.write(f"Data Sekunder (Real-world): {secondary_results['file_name']}\n")
        f.write(f"Total Signatures Analyzed: {primary_results['total_signatures'] + secondary_results['total_signatures']:,}\n\n")
        
        # Detail hasil
        f.write("DETAIL HASIL ANALISIS\n")
        f.write("=" * 30 + "\n\n")
        
        for dataset_name, results in [("DATA PRIMER", primary_results), ("DATA SEKUNDER", secondary_results)]:
            f.write(f"{dataset_name}\n")
            f.write("-" * len(dataset_name) + "\n")
            f.write(f"File: {results['file_name']}\n")
            f.write(f"Dataset Type: {results['dataset_type']}\n")
            f.write(f"Total Signatures: {results['total_signatures']:,}\n")
            f.write(f"Unique R Components: {results['unique_r']:,}\n")
            f.write(f"Duplicate R Components: {results['duplicate_r']}\n")
            f.write(f"Duplicate Rate: {results['duplicate_rate']:.4f}%\n")
            f.write(f"Chi-Squared Statistic: {results['chi2_stat']:.6f}\n")
            f.write(f"P-Value: {results['p_value']:.6f}\n")
            f.write(f"Interpretation: {results['chi2_interpretation']}\n")
            f.write(f"Shannon Entropy: {results['entropy']:.4f}\n")
            f.write(f"Entropy Ratio: {results['entropy_ratio']:.2%}\n")
            f.write(f"Repeated Prefixes: {results['repeated_prefixes_count']}\n")
            f.write(f"Risk Score: {results['risk_score']}/100\n")
            f.write(f"Risk Level: {results['risk_level']}\n")
            f.write(f"Risk Factors: {', '.join(results['risk_factors']) if results['risk_factors'] else 'None'}\n")
            f.write("\n")
        
        f.write("End of Report\n")
        f.write("=" * 100 + "\n")
    
    print(f"\n💾 Hasil analisis disimpan ke: {output_file}")
    return output_file

def main():
    """Fungsi utama untuk analisis komparatif"""
    print("🔍 ANALISIS KOMPARATIF NONCE REUSE")
    print("Data Primer vs Data Sekunder")
    print("=" * 60)
    
    # File yang akan dianalisis
    primary_file = "nonce_forensic_bit-flip_500k.csv"
    secondary_file = "nonce_forensic_log_100k_bybit.csv"
    
    # Analisis data primer
    primary_results = analyze_dataset(primary_file, "Data Primer (Eksperimental)")
    
    # Analisis data sekunder
    secondary_results = analyze_dataset(secondary_file, "Data Sekunder (Real-world)")
    
    if primary_results and secondary_results:
        # Generate tabel perbandingan
        generate_comparative_table(primary_results, secondary_results)
        
        # Simpan hasil
        output_file = save_results_to_file(primary_results, secondary_results)
        
        print(f"\n" + "=" * 100)
        print("🏁 ANALISIS KOMPARATIF SELESAI")
        print("=" * 100)
        print("📋 Metrik pengujian yang konsisten telah diterapkan pada kedua dataset")
        print("💾 Hasil dapat digunakan langsung untuk dokumentasi skripsi")
    else:
        print("❌ Gagal menganalisis salah satu atau kedua dataset")

if __name__ == "__main__":
    main()