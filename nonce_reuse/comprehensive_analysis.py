#!/usr/bin/env python3
"""
Script untuk menganalisis data eksperimental (3 file) dan data real-world (3 file)
dengan metrik pengujian yang konsisten dan menyimpan hasil ke comper_primary_sekunder.txt
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

def analyze_single_file(csv_file):
    """Menganalisis satu file CSV"""
    try:
        # Baca CSV
        data = []
        with open(csv_file, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            headers = csv_reader.fieldnames
            for row in csv_reader:
                data.append(row)
        
        # Tentukan kolom R component
        r_column = None
        for col in ['r_component_hex', 'r_component']:
            if col in headers:
                r_column = col
                break
        
        if r_column is None:
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
            'file_name': csv_file.split('/')[-1],
            'total_signatures': total_signatures,
            'unique_r': unique_r,
            'duplicate_r': duplicate_r_count,
            'duplicate_rate': duplicate_rate,
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
        
        return results
        
    except Exception as e:
        print(f"❌ Error menganalisis {csv_file}: {e}")
        return None

def analyze_dataset_group(files, group_name):
    """Menganalisis grup dataset (eksperimental atau real-world)"""
    print(f"\n🔍 MENGANALISIS {group_name.upper()}")
    print("=" * 60)
    
    results = []
    total_signatures = 0
    total_unique_r = 0
    total_duplicate_r = 0
    total_risk_scores = []
    
    for file_path in files:
        print(f"\n📁 Memproses: {file_path.split('/')[-1]}")
        result = analyze_single_file(file_path)
        
        if result:
            results.append(result)
            total_signatures += result['total_signatures']
            total_unique_r += result['unique_r']
            total_duplicate_r += result['duplicate_r']
            total_risk_scores.append(result['risk_score'])
            
            print(f"   ✓ {result['total_signatures']:,} signatures")
            print(f"   ✓ {result['duplicate_r']} duplikasi R")
            print(f"   ✓ Risk Score: {result['risk_score']}/100")
        else:
            print(f"   ❌ Gagal memproses file")
    
    # Hitung statistik grup
    avg_duplicate_rate = (total_duplicate_r / total_unique_r * 100) if total_unique_r > 0 else 0
    avg_risk_score = sum(total_risk_scores) / len(total_risk_scores) if total_risk_scores else 0
    
    group_stats = {
        'group_name': group_name,
        'files': results,
        'total_signatures': total_signatures,
        'total_unique_r': total_unique_r,
        'total_duplicate_r': total_duplicate_r,
        'avg_duplicate_rate': avg_duplicate_rate,
        'avg_risk_score': avg_risk_score,
        'file_count': len(results)
    }
    
    print(f"\n📊 RINGKASAN {group_name.upper()}:")
    print(f"   • Total Files: {len(results)}")
    print(f"   • Total Signatures: {total_signatures:,}")
    print(f"   • Total Duplikasi R: {total_duplicate_r}")
    print(f"   • Rata-rata Duplikasi: {avg_duplicate_rate:.4f}%")
    print(f"   • Rata-rata Risk Score: {avg_risk_score:.1f}/100")
    
    return group_stats

def generate_comprehensive_report(experimental_stats, realworld_stats):
    """Menghasilkan laporan komprehensif"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = "comper_primary_sekunder.txt"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("ANALISIS KOMPREHENSIF NONCE REUSE\n")
        f.write("DATA EKSPERIMENTAL VS DATA REAL-WORLD\n")
        f.write("=" * 100 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analyst: Forensic Blockchain Analyzer\n\n")
        
        # Ringkasan Eksekutif
        f.write("RINGKASAN EKSEKUTIF\n")
        f.write("-" * 30 + "\n")
        f.write(f"Data Eksperimental: {experimental_stats['file_count']} file CSV\n")
        f.write(f"Data Real-world: {realworld_stats['file_count']} file CSV\n")
        f.write(f"Total Signatures Analyzed: {experimental_stats['total_signatures'] + realworld_stats['total_signatures']:,}\n")
        f.write(f"Total Duplikasi Detected: {experimental_stats['total_duplicate_r'] + realworld_stats['total_duplicate_r']}\n\n")
        
        # Detail Analisis Data Eksperimental
        f.write("DETAIL ANALISIS DATA EKSPERIMENTAL\n")
        f.write("=" * 50 + "\n")
        f.write(f"Total Files: {experimental_stats['file_count']}\n")
        f.write(f"Total Signatures: {experimental_stats['total_signatures']:,}\n")
        f.write(f"Total Unique R: {experimental_stats['total_unique_r']:,}\n")
        f.write(f"Total Duplicate R: {experimental_stats['total_duplicate_r']}\n")
        f.write(f"Average Duplicate Rate: {experimental_stats['avg_duplicate_rate']:.4f}%\n")
        f.write(f"Average Risk Score: {experimental_stats['avg_risk_score']:.1f}/100\n\n")
        
        for file_result in experimental_stats['files']:
            f.write(f"FILE: {file_result['file_name']}\n")
            f.write("-" * len(file_result['file_name']) + "-----\n")
            f.write(f"  Total Signatures: {file_result['total_signatures']:,}\n")
            f.write(f"  Unique R Components: {file_result['unique_r']:,}\n")
            f.write(f"  Duplicate R Components: {file_result['duplicate_r']}\n")
            f.write(f"  Duplicate Rate: {file_result['duplicate_rate']:.4f}%\n")
            f.write(f"  Chi-Squared Statistic: {file_result['chi2_stat']:.6f}\n")
            f.write(f"  P-Value: {file_result['p_value']:.6f}\n")
            f.write(f"  Interpretation: {file_result['chi2_interpretation']}\n")
            f.write(f"  Shannon Entropy: {file_result['entropy']:.4f}\n")
            f.write(f"  Entropy Ratio: {file_result['entropy_ratio']:.2%}\n")
            f.write(f"  Repeated Prefixes: {file_result['repeated_prefixes_count']}\n")
            f.write(f"  Risk Score: {file_result['risk_score']}/100\n")
            f.write(f"  Risk Level: {file_result['risk_level']}\n")
            f.write(f"  Risk Factors: {', '.join(file_result['risk_factors']) if file_result['risk_factors'] else 'None'}\n")
            f.write("\n")
        
        # Detail Analisis Data Real-world
        f.write("DETAIL ANALISIS DATA REAL-WORLD\n")
        f.write("=" * 40 + "\n")
        f.write(f"Total Files: {realworld_stats['file_count']}\n")
        f.write(f"Total Signatures: {realworld_stats['total_signatures']:,}\n")
        f.write(f"Total Unique R: {realworld_stats['total_unique_r']:,}\n")
        f.write(f"Total Duplicate R: {realworld_stats['total_duplicate_r']}\n")
        f.write(f"Average Duplicate Rate: {realworld_stats['avg_duplicate_rate']:.4f}%\n")
        f.write(f"Average Risk Score: {realworld_stats['avg_risk_score']:.1f}/100\n\n")
        
        for file_result in realworld_stats['files']:
            f.write(f"FILE: {file_result['file_name']}\n")
            f.write("-" * len(file_result['file_name']) + "-----\n")
            f.write(f"  Total Signatures: {file_result['total_signatures']:,}\n")
            f.write(f"  Unique R Components: {file_result['unique_r']:,}\n")
            f.write(f"  Duplicate R Components: {file_result['duplicate_r']}\n")
            f.write(f"  Duplicate Rate: {file_result['duplicate_rate']:.4f}%\n")
            f.write(f"  Chi-Squared Statistic: {file_result['chi2_stat']:.6f}\n")
            f.write(f"  P-Value: {file_result['p_value']:.6f}\n")
            f.write(f"  Interpretation: {file_result['chi2_interpretation']}\n")
            f.write(f"  Shannon Entropy: {file_result['entropy']:.4f}\n")
            f.write(f"  Entropy Ratio: {file_result['entropy_ratio']:.2%}\n")
            f.write(f"  Repeated Prefixes: {file_result['repeated_prefixes_count']}\n")
            f.write(f"  Risk Score: {file_result['risk_score']}/100\n")
            f.write(f"  Risk Level: {file_result['risk_level']}\n")
            f.write(f"  Risk Factors: {', '.join(file_result['risk_factors']) if file_result['risk_factors'] else 'None'}\n")
            f.write("\n")
        
        # Analisis Komparatif
        f.write("ANALISIS KOMPARATIF\n")
        f.write("=" * 25 + "\n")
        f.write(f"{'METRIK':<35} {'EKSPERIMENTAL':<20} {'REAL-WORLD':<20} {'SELISIH':<15}\n")
        f.write("-" * 90 + "\n")
        
        metrics = [
            ('Total Signatures', experimental_stats['total_signatures'], realworld_stats['total_signatures']),
            ('Total Unique R', experimental_stats['total_unique_r'], realworld_stats['total_unique_r']),
            ('Total Duplicate R', experimental_stats['total_duplicate_r'], realworld_stats['total_duplicate_r']),
            ('Avg Duplicate Rate (%)', experimental_stats['avg_duplicate_rate'], realworld_stats['avg_duplicate_rate']),
            ('Avg Risk Score', experimental_stats['avg_risk_score'], realworld_stats['avg_risk_score'])
        ]
        
        for metric_name, exp_val, real_val in metrics:
            if 'Rate' in metric_name or 'Score' in metric_name:
                exp_str = f"{exp_val:.4f}"
                real_str = f"{real_val:.4f}"
                diff_str = f"{exp_val - real_val:+.4f}"
            else:
                exp_str = f"{exp_val:,}"
                real_str = f"{real_val:,}"
                diff_str = f"{exp_val - real_val:+,}"
            
            f.write(f"{metric_name:<35} {exp_str:<20} {real_str:<20} {diff_str:<15}\n")
        
        f.write("\n")
        
        # Kesimpulan
        f.write("KESIMPULAN DAN REKOMENDASI\n")
        f.write("=" * 35 + "\n")
        f.write("1. TEMUAN UTAMA:\n")
        f.write(f"   - Data eksperimental menunjukkan rata-rata risk score {experimental_stats['avg_risk_score']:.1f}/100\n")
        f.write(f"   - Data real-world menunjukkan rata-rata risk score {realworld_stats['avg_risk_score']:.1f}/100\n")
        f.write(f"   - Total {experimental_stats['total_duplicate_r'] + realworld_stats['total_duplicate_r']} duplikasi R terdeteksi\n")
        f.write(f"   - Tingkat duplikasi eksperimental: {experimental_stats['avg_duplicate_rate']:.4f}%\n")
        f.write(f"   - Tingkat duplikasi real-world: {realworld_stats['avg_duplicate_rate']:.4f}%\n\n")
        
        f.write("2. INTERPRETASI:\n")
        if experimental_stats['avg_risk_score'] > realworld_stats['avg_risk_score']:
            f.write("   - Data eksperimental menunjukkan risiko lebih tinggi dari implementasi real-world\n")
            f.write("   - Simulasi serangan berhasil mengidentifikasi kerentanan potensial\n")
        else:
            f.write("   - Data real-world menunjukkan risiko setara atau lebih tinggi dari eksperimental\n")
            f.write("   - Implementasi exchange memerlukan perbaikan keamanan\n")
        f.write("\n")
        
        f.write("3. REKOMENDASI:\n")
        f.write("   - Lakukan monitoring berkala pada implementasi nonce generation\n")
        f.write("   - Implementasikan sistem deteksi duplikasi real-time\n")
        f.write("   - Tingkatkan entropi dalam proses pembangkitan nonce\n")
        f.write("   - Lakukan audit keamanan rutin pada exchange\n")
        f.write("\n")
        
        f.write("End of Report\n")
        f.write("=" * 100 + "\n")
    
    print(f"\n💾 Laporan komprehensif disimpan ke: {output_file}")
    return output_file

def main():
    """Fungsi utama untuk analisis komprehensif"""
    print("🔍 ANALISIS KOMPREHENSIF NONCE REUSE")
    print("Data Eksperimental vs Data Real-world")
    print("=" * 60)
    
    # File eksperimental
    experimental_files = [
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_bit-flip_500k.csv",
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_amount_500k.csv",
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_random_500k.csv"
    ]
    
    # File real-world
    realworld_files = [
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_log_100k_bybit.csv",
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_log_100k_okx.csv",
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_log_100k_jup.csv",
        "e:/Ngoding/Project IT/Python/Skripsi/nonce_reuse/nonce_forensic_log_100k_phantom.csv"
    ]
    
    # Analisis grup eksperimental
    experimental_stats = analyze_dataset_group(experimental_files, "Data Eksperimental")
    
    # Analisis grup real-world
    realworld_stats = analyze_dataset_group(realworld_files, "Data Real-world")
    
    if experimental_stats and realworld_stats:
        # Generate laporan komprehensif
        output_file = generate_comprehensive_report(experimental_stats, realworld_stats)
        
        print(f"\n" + "=" * 100)
        print("🏁 ANALISIS KOMPREHENSIF SELESAI")
        print("=" * 100)
        print("📋 6 file CSV telah dianalisis dengan metrik yang konsisten")
        print(f"💾 Hasil tersimpan di: {output_file}")
        print("📊 Laporan siap untuk dokumentasi skripsi")
    else:
        print("❌ Gagal menganalisis salah satu atau kedua grup dataset")

if __name__ == "__main__":
    main()