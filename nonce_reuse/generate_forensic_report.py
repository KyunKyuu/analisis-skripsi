#!/usr/bin/env python3
"""
Script untuk menghasilkan laporan forensik lengkap untuk dokumentasi skripsi.
Menganalisis semua exchange dan menyimpan hasil ke file.
"""

import pandas as pd
import numpy as np
from collections import Counter
from scipy import stats
from datetime import datetime
import os
import sys

try:
    from config import HELIUS_API_KEY
except ImportError:
    print("ERROR: File config.py tidak ditemukan atau HELIUS_API_KEY tidak terdefinisi.")
    sys.exit(1)

def perform_chi_squared_test(r_components):
    """Melakukan uji Chi-Squared pada distribusi byte pertama dari komponen R."""
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
    
    return chi2_stat, p_value, interpretation, detailed_stats

def analyze_exchange(csv_file, exchange_name):
    """Menganalisis satu exchange dan mengembalikan hasil."""
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        return None
    except Exception as e:
        return None
    
    # Validasi kolom
    required_columns = ['signature_hash', 'r_component_hex']
    missing_required = [col for col in required_columns if col not in df.columns]
    if missing_required:
        return None
    
    has_message_hash = 'message_hash_hex' in df.columns
    
    # Analisis duplikasi R components
    r_counts = df['r_component_hex'].value_counts()
    duplicate_r = r_counts[r_counts > 1]
    
    total_signatures = len(df)
    unique_r = df['r_component_hex'].nunique()
    duplicate_r_count = len(duplicate_r)
    duplicate_rate = (duplicate_r_count / unique_r * 100) if unique_r > 0 else 0
    
    # Analisis message hash jika tersedia
    message_stats = {}
    if has_message_hash:
        message_counts = df['message_hash_hex'].value_counts()
        duplicate_messages = message_counts[message_counts > 1]
        
        unique_messages = df['message_hash_hex'].nunique()
        duplicate_message_count = len(duplicate_messages)
        message_duplicate_rate = (duplicate_message_count / unique_messages * 100) if unique_messages > 0 else 0
        
        message_stats = {
            'unique_messages': unique_messages,
            'duplicate_messages': duplicate_message_count,
            'message_duplicate_rate': message_duplicate_rate
        }
    
    # Uji Chi-Squared
    chi2_stat, p_value, interpretation, chi2_details = perform_chi_squared_test(df['r_component_hex'].tolist())
    
    # Analisis entropi
    combined_hex = ''.join(df['r_component_hex'].astype(str))
    char_counts = Counter(combined_hex)
    total_chars = len(combined_hex)
    
    entropy = 0
    for count in char_counts.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * np.log2(p)
    
    max_entropy = 4.0
    entropy_ratio = entropy / max_entropy if entropy > 0 else 0
    
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
    
    if duplicate_r_count > total_signatures * 0.01:
        risk_score += 25
        risk_factors.append("Tingkat duplikasi tinggi")
    
    # Level risiko
    if risk_score >= 70:
        risk_level = "TINGGI"
    elif risk_score >= 40:
        risk_level = "SEDANG"
    else:
        risk_level = "RENDAH"
    
    return {
        'exchange': exchange_name,
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
        'message_stats': message_stats,
        'chi2_details': chi2_details
    }

def generate_report_file(results, output_file):
    """Menghasilkan file laporan lengkap."""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 100 + "\n")
        f.write("LAPORAN FORENSIK NONCE REUSE ANALYSIS - SOLANA BLOCKCHAIN\n")
        f.write("=" * 100 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analyst: Forensic Blockchain Analyzer\n")
        f.write(f"Scope: Multi-Exchange Nonce Reuse Detection\n")
        f.write("=" * 100 + "\n\n")
        
        # Executive Summary
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 50 + "\n")
        valid_results = [r for r in results if r]
        total_signatures = sum(r['total_signatures'] for r in valid_results)
        total_duplicates = sum(r['duplicate_r'] for r in valid_results)
        avg_duplicate_rate = np.mean([r['duplicate_rate'] for r in valid_results])
        
        f.write(f"• Total Signatures Analyzed: {total_signatures:,}\n")
        f.write(f"• Total Duplicate R Components: {total_duplicates}\n")
        f.write(f"• Average Duplicate Rate: {avg_duplicate_rate:.4f}%\n")
        f.write(f"• Exchanges Analyzed: {len(valid_results)}\n")
        
        high_risk = [r for r in valid_results if r['risk_score'] >= 40]
        f.write(f"• High Risk Exchanges: {len(high_risk)}\n\n")
        
        # Detailed Analysis per Exchange
        f.write("DETAILED ANALYSIS PER EXCHANGE\n")
        f.write("=" * 50 + "\n\n")
        
        for result in valid_results:
            f.write(f"EXCHANGE: {result['exchange']}\n")
            f.write("-" * 30 + "\n")
            f.write(f"File: {result['file_name']}\n")
            f.write(f"Total Signatures: {result['total_signatures']:,}\n")
            f.write(f"Unique R Components: {result['unique_r']:,}\n")
            f.write(f"Duplicate R Components: {result['duplicate_r']}\n")
            f.write(f"Duplicate Rate: {result['duplicate_rate']:.4f}%\n")
            f.write(f"Risk Level: {result['risk_level']}\n")
            f.write(f"Risk Score: {result['risk_score']}/100\n")
            
            if result['risk_factors']:
                f.write("Risk Factors:\n")
                for factor in result['risk_factors']:
                    f.write(f"  - {factor}\n")
            
            f.write(f"\nStatistical Analysis:\n")
            f.write(f"  Chi-Squared Statistic: {result['chi2_stat']:.6f}\n")
            f.write(f"  P-Value: {result['p_value']:.6f}\n")
            f.write(f"  Interpretation: {result['interpretation']}\n")
            f.write(f"  Shannon Entropy: {result['entropy']:.4f}\n")
            f.write(f"  Entropy Ratio: {result['entropy_ratio']*100:.2f}%\n")
            
            if result['has_message_hash'] and result['message_stats']:
                f.write(f"\nMessage Hash Analysis:\n")
                f.write(f"  Unique Messages: {result['message_stats']['unique_messages']:,}\n")
                f.write(f"  Duplicate Messages: {result['message_stats']['duplicate_messages']}\n")
                f.write(f"  Message Duplicate Rate: {result['message_stats']['message_duplicate_rate']:.4f}%\n")
            
            f.write("\n" + "="*50 + "\n\n")
        
        # Comparative Analysis
        f.write("COMPARATIVE ANALYSIS\n")
        f.write("=" * 30 + "\n")
        f.write(f"{'Exchange':<15} {'Total Sig':<12} {'Unique R':<12} {'Dup R':<8} {'Dup Rate':<12} {'Risk':<10}\n")
        f.write("-" * 80 + "\n")
        
        for result in valid_results:
            f.write(f"{result['exchange']:<15} {result['total_signatures']:<12,} {result['unique_r']:<12,} "
                   f"{result['duplicate_r']:<8} {result['duplicate_rate']:<12.4f}% {result['risk_level']:<10}\n")
        
        f.write("\n")
        
        # Statistical Summary
        if len(valid_results) > 1:
            dup_rates = [r['duplicate_rate'] for r in valid_results]
            entropies = [r['entropy_ratio'] for r in valid_results]
            p_values = [r['p_value'] for r in valid_results]
            
            f.write("STATISTICAL SUMMARY\n")
            f.write("-" * 30 + "\n")
            f.write(f"Duplicate Rate Statistics:\n")
            f.write(f"  Mean: {np.mean(dup_rates):.4f}%\n")
            f.write(f"  Std Dev: {np.std(dup_rates):.4f}%\n")
            f.write(f"  Min: {min(dup_rates):.4f}%\n")
            f.write(f"  Max: {max(dup_rates):.4f}%\n")
            
            f.write(f"\nEntropy Statistics:\n")
            f.write(f"  Mean Entropy Ratio: {np.mean(entropies)*100:.2f}%\n")
            f.write(f"  Std Dev: {np.std(entropies)*100:.2f}%\n")
            
            f.write(f"\nChi-Squared P-Value Statistics:\n")
            f.write(f"  Mean P-Value: {np.mean(p_values):.6f}\n")
            f.write(f"  Min P-Value: {min(p_values):.6f}\n")
            f.write(f"  Max P-Value: {max(p_values):.6f}\n")
        
        # Conclusions and Recommendations
        f.write("\n\nCONCLUSIONS AND RECOMMENDATIONS\n")
        f.write("=" * 40 + "\n")
        
        if not high_risk:
            f.write("✅ OVERALL ASSESSMENT: LOW RISK\n")
            f.write("All analyzed exchanges show acceptable levels of nonce randomness.\n")
            f.write("No significant nonce reuse vulnerabilities detected.\n\n")
            f.write("RECOMMENDATIONS:\n")
            f.write("• Continue routine monitoring\n")
            f.write("• Maintain current security practices\n")
            f.write("• Schedule periodic re-assessment\n")
        else:
            f.write("⚠️  OVERALL ASSESSMENT: ATTENTION REQUIRED\n")
            f.write("Some exchanges show elevated risk factors.\n\n")
            f.write("HIGH RISK EXCHANGES:\n")
            for exchange in high_risk:
                f.write(f"• {exchange['exchange']}: Score {exchange['risk_score']}/100\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            f.write("• Implement enhanced monitoring for high-risk exchanges\n")
            f.write("• Investigate nonce generation mechanisms\n")
            f.write("• Consider additional security measures\n")
        
        f.write(f"\n\nReport generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("End of Report\n")
        f.write("=" * 100 + "\n")

def main():
    """Fungsi utama untuk menghasilkan laporan forensik."""
    print("🔍 GENERATING COMPREHENSIVE FORENSIC REPORT")
    print("=" * 60)
    
    # Daftar exchange yang akan dianalisis
    exchanges = [
        ("nonce_forensic_log_100k_bybit.csv", "BYBIT"),
        ("nonce_forensic_log_100k_jup.csv", "JUPITER"), 
        ("nonce_forensic_log_100k_okx.csv", "OKX")
    ]
    
    results = []
    
    print("📊 Analyzing exchanges...")
    for csv_file, exchange_name in exchanges:
        print(f"   • Processing {exchange_name}...")
        result = analyze_exchange(csv_file, exchange_name)
        if result:
            results.append(result)
            print(f"     ✅ {exchange_name}: {result['total_signatures']:,} signatures, {result['duplicate_r']} duplicates")
        else:
            print(f"     ❌ {exchange_name}: Failed to process")
    
    # Generate report file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"forensic_report_{timestamp}.txt"
    
    print(f"\n📝 Generating report file: {output_file}")
    generate_report_file(results, output_file)
    
    print(f"✅ Report generated successfully!")
    print(f"📂 File saved: {output_file}")
    print(f"📊 Total exchanges analyzed: {len(results)}")
    
    # Display summary
    if results:
        total_sigs = sum(r['total_signatures'] for r in results)
        total_dups = sum(r['duplicate_r'] for r in results)
        print(f"📈 Summary: {total_sigs:,} signatures, {total_dups} duplicates")

if __name__ == "__main__":
    main()