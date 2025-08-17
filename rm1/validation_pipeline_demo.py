#!/usr/bin/env python3
"""
validation_pipeline_demo.py

Script demo untuk menunjukkan penggunaan pipeline verifikasi otomatis
dengan multiple alamat dan batch processing.

Author: Expert Python Developer
Purpose: Demo Pipeline Verifikasi Drain Wallet
"""

import os
import sys
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any

# Import fungsi dari drainer_check.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from drainer_check import (
    load_transaction_data,
    perform_heuristic_analysis,
    calculate_all_metrics,
    run_validation_pipeline,
    save_validation_results_to_csv,
    generate_validation_report,
    log_info,
    VALIDATION_STATUS
)

def batch_validation_demo():
    """
    Demo batch validation untuk multiple alamat.
    """
    print("="*80)
    print("🔍 DEMO PIPELINE VERIFIKASI OTOMATIS - BATCH PROCESSING")
    print("="*80)
    
    # Contoh alamat untuk demo (gunakan alamat yang ada di file CSV Anda)
    demo_addresses = [
        "2PvbiHwbj6kcVwwwM6y6ApVij587LmZ5xmQReh9aGDtc",  # Alamat yang sudah diverifikasi
        "ConfnKVMDysrY7UqtLw35zafLyLq3txAQ7y2iSzCrWyk",  # Alamat yang sudah diverifikasi
        "FbpCfLxM7umSbfYKXPtN3RSkMdmcdt6ifEEqC3dZGhLB",  # Alamat yang sudah diverifikasi
    ]
    
    # File CSV yang akan dianalisis (sesuaikan dengan file yang ada)
    csv_files = [
        "2PvbiHwbj6kcVwwwM6y6ApVij587LmZ5xmQReh9aGDtc_transactions.csv",
        "ConfnKVMDysrY7UqtLw35zafLyLq3txAQ7y2iSzCrWyk_transactions.csv", 
        "FbpCfLxM7umSbfYKXPtN3RSkMdmcdt6ifEEqC3dZGhLB_transactions.csv"
    ]
    
    validation_results = []
    
    for i, (address, csv_file) in enumerate(zip(demo_addresses, csv_files), 1):
        print(f"\n{'='*80}")
        print(f"📊 ANALISIS {i}/{len(demo_addresses)}: {address[:16]}...")
        print(f"📁 File: {csv_file}")
        print(f"{'='*80}")
        
        try:
            # Cek apakah file ada
            if not os.path.exists(csv_file):
                log_info(f"⚠️ File tidak ditemukan: {csv_file}, skip...")
                continue
            
            # Load data transaksi
            df = load_transaction_data(csv_file)
            
            # Analisis heuristik
            heuristic_result = perform_heuristic_analysis(df, address, csv_file)
            
            # Hitung metrik
            metrics = calculate_all_metrics(df, address)
            
            # Jalankan pipeline verifikasi
            validation_result = run_validation_pipeline(address, heuristic_result, metrics)
            validation_results.append(validation_result)
            
            # Tampilkan ringkasan
            print(f"\n📋 RINGKASAN VALIDASI:")
            print(f"   Status: {validation_result['validation_status'].upper()}")
            print(f"   Confidence: {validation_result['confidence_score']:.2f}")
            print(f"   Rekomendasi: {validation_result['final_recommendation']}")
            
            if validation_result['manual_checklist']:
                priority = validation_result['manual_checklist']['priority_level']
                print(f"   Manual Review: Required (Priority: {priority.upper()})")
            
        except Exception as e:
            log_info(f"❌ Error saat menganalisis {address}: {e}")
            continue
    
    # Simpan hasil batch ke CSV
    if validation_results:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = f"batch_validation_results_{timestamp}.csv"
        save_validation_results_to_csv(validation_results, csv_file)
        
        print(f"\n{'='*80}")
        print("📊 RINGKASAN BATCH VALIDATION")
        print(f"{'='*80}")
        print(f"Total alamat dianalisis: {len(validation_results)}")
        
        # Hitung statistik
        verified_count = sum(1 for r in validation_results if r['validation_status'] == VALIDATION_STATUS['VERIFIED'])
        suspect_count = sum(1 for r in validation_results if r['validation_status'] == VALIDATION_STATUS['SUSPECT'])
        rejected_count = sum(1 for r in validation_results if r['validation_status'] == VALIDATION_STATUS['REJECTED'])
        manual_review_count = sum(1 for r in validation_results if r['manual_checklist'] is not None)
        
        print(f"✅ Verified: {verified_count}")
        print(f"⚠️ Suspect: {suspect_count}")
        print(f"❌ Rejected: {rejected_count}")
        print(f"📝 Requires Manual Review: {manual_review_count}")
        print(f"📁 Hasil disimpan ke: {csv_file}")
        print(f"{'='*80}")

def single_address_demo():
    """
    Demo validasi untuk satu alamat dengan laporan detail.
    """
    print("="*80)
    print("🔍 DEMO PIPELINE VERIFIKASI OTOMATIS - SINGLE ADDRESS")
    print("="*80)
    
    # Contoh alamat dan file (sesuaikan dengan data yang ada)
    demo_address = "2PvbiHwbj6kcVwwwM6y6ApVij587LmZ5xmQReh9aGDtc"
    demo_csv = "2PvbiHwbj6kcVwwwM6y6ApVij587LmZ5xmQReh9aGDtc_transactions.csv"
    
    try:
        if not os.path.exists(demo_csv):
            print(f"⚠️ File demo tidak ditemukan: {demo_csv}")
            print("💡 Silakan sesuaikan nama file di dalam script ini.")
            return
        
        # Load data
        df = load_transaction_data(demo_csv)
        
        # Analisis heuristik
        heuristic_result = perform_heuristic_analysis(df, demo_address, demo_csv)
        
        # Hitung metrik
        metrics = calculate_all_metrics(df, demo_address)
        
        # Pipeline verifikasi
        validation_result = run_validation_pipeline(demo_address, heuristic_result, metrics)
        
        # Generate dan tampilkan laporan detail
        detailed_report = generate_validation_report(validation_result)
        print(detailed_report)
        
        # Simpan laporan ke file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"validation_report_{demo_address[:8]}_{timestamp}.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(detailed_report)
        
        print(f"\n💾 Laporan detail disimpan ke: {report_file}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def validation_status_explanation():
    """
    Menjelaskan arti dari setiap validation status.
    """
    print("="*80)
    print("📚 PENJELASAN VALIDATION STATUS")
    print("="*80)
    
    explanations = {
        'verified': {
            'emoji': '✅',
            'meaning': 'VERIFIED',
            'description': 'Alamat telah terverifikasi sebagai drainer berdasarkan multiple indicators',
            'criteria': [
                'Semua atau sebagian besar heuristik terpenuhi',
                'Ditemukan dalam database alamat terverifikasi',
                'Dikonfirmasi oleh database pihak ketiga',
                'Memenuhi threshold auto-verification'
            ]
        },
        'suspect': {
            'emoji': '⚠️',
            'meaning': 'SUSPECT',
            'description': 'Alamat mencurigakan dan memerlukan investigasi manual lebih lanjut',
            'criteria': [
                'Beberapa heuristik terpenuhi namun tidak semua',
                'Pola transaksi mencurigakan namun tidak konklusif',
                'Memerlukan cross-reference dengan sumber eksternal',
                'Confidence score di bawah threshold auto-verification'
            ]
        },
        'rejected': {
            'emoji': '❌',
            'meaning': 'REJECTED',
            'description': 'Alamat tidak memenuhi kriteria sebagai drainer',
            'criteria': [
                'Tidak ada heuristik yang terpenuhi',
                'Terdaftar dalam blacklist (legitimate service)',
                'Pola transaksi normal/tidak mencurigakan',
                'Tidak ditemukan indikasi aktivitas jahat'
            ]
        }
    }
    
    for status, info in explanations.items():
        print(f"\n{info['emoji']} {info['meaning']}")
        print("-" * 40)
        print(f"Deskripsi: {info['description']}")
        print("\nKriteria:")
        for criterion in info['criteria']:
            print(f"  • {criterion}")
        print()

def main():
    """
    Fungsi utama demo.
    """
    print("🚀 DEMO PIPELINE VERIFIKASI DRAIN WALLET")
    print("Pilih mode demo:")
    print("1. Single Address Demo (analisis detail satu alamat)")
    print("2. Batch Validation Demo (analisis multiple alamat)")
    print("3. Validation Status Explanation (penjelasan status)")
    print("4. Exit")
    
    while True:
        try:
            choice = input("\nPilih opsi (1-4): ").strip()
            
            if choice == '1':
                single_address_demo()
                break
            elif choice == '2':
                batch_validation_demo()
                break
            elif choice == '3':
                validation_status_explanation()
                break
            elif choice == '4':
                print("👋 Terima kasih!")
                break
            else:
                print("❌ Pilihan tidak valid. Silakan pilih 1-4.")
                
        except KeyboardInterrupt:
            print("\n👋 Demo dihentikan oleh user.")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            break

if __name__ == "__main__":
    main()