#!/usr/bin/env python3
"""
drainer_heuristic_validator.py

Script untuk menganalisis data transaksi dan memvalidasi apakah alamat memenuhi
kriteria heuristik sebagai drain wallet dengan klasifikasi tipologi serangan.

Author: Expert Python Developer
Purpose: RM 1 - Analisis Pola Transaksi Drain Wallet dengan Klasifikasi Tipologi
"""

import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any, List
import os
import json

# =============================================================================
# KONFIGURASI HEURISTIK (THRESHOLDS)
# =============================================================================

# Heuristik 1: Pola Penerimaan Masif
MIN_UNIQUE_VICTIMS = 20

# Heuristik 2: Pola Konsolidasi Cepat  
MAX_CONSOLIDATION_DELAY_HOURS = 0.45

# Heuristik 3: Diversitas Aset
MIN_ASSET_DIVERSITY = 3

# Konfigurasi Klasifikasi Tipologi Serangan
MASS_DRAINER_VICTIM_THRESHOLD = 50
SOPHISTICATED_LAUNDERING_OUTGOING_THRESHOLD = 10
MULTI_VECTOR_UNIQUE_ASSETS_THRESHOLD = 5

# =============================================================================
# FUNGSI UTILITAS
# =============================================================================

def log_info(message: str) -> None:
    """
    Mencetak informasi log dengan timestamp ke konsol.
    
    Args:
        message (str): Pesan yang akan ditampilkan
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def load_transaction_data(file_path: str) -> pd.DataFrame:
    """
    Memuat data transaksi dari file CSV dan melakukan preprocessing.
    
    Args:
        file_path (str): Path ke file CSV
        
    Returns:
        pd.DataFrame: DataFrame dengan data transaksi yang sudah diproses
        
    Raises:
        FileNotFoundError: Jika file tidak ditemukan
        ValueError: Jika format data tidak valid
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File tidak ditemukan: {file_path}")
    
    log_info(f"Memuat data dari file: {file_path}")
    
    try:
        # Load CSV
        df = pd.read_csv(file_path)
        
        # Validasi kolom yang diperlukan
        required_columns = [
            'tx_hash', 'timestamp_utc', 'source_address', 
            'destination_address', 'amount', 'token_mint_address', 'transaction_type'
        ]
        
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Kolom yang diperlukan tidak ditemukan: {missing_columns}")
        
        # Konversi timestamp ke datetime
        df['timestamp_utc'] = pd.to_datetime(df['timestamp_utc'])
        
        # Konversi amount ke numeric
        df['amount'] = pd.to_numeric(df['amount'], errors='coerce')
        
        # Filter baris dengan data yang valid
        initial_rows = len(df)
        df = df.dropna(subset=['timestamp_utc', 'source_address', 'destination_address', 'amount'])
        final_rows = len(df)
        
        if initial_rows != final_rows:
            log_info(f"Filtered {initial_rows - final_rows} baris dengan data tidak valid")
        
        log_info(f"Berhasil memuat {len(df)} transaksi")
        return df
        
    except Exception as e:
        raise ValueError(f"Error saat memuat data: {e}")

# =============================================================================
# IMPLEMENTASI HEURISTIK
# =============================================================================

def analyze_massive_reception_pattern(df: pd.DataFrame, target_address: str) -> Tuple[bool, int, str]:
    """
    Heuristik 1: Menganalisis pola penerimaan masif.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat target yang dianalisis
        
    Returns:
        Tuple[bool, int, str]: (terpenuhi, jumlah_korban_unik, penjelasan)
    """
    log_info("Menganalisis Heuristik 1: Pola Penerimaan Masif...")
    
    # Filter transaksi masuk ke alamat target
    incoming_txs = df[df['destination_address'] == target_address]
    
    if incoming_txs.empty:
        return False, 0, "Tidak ada transaksi masuk ke alamat target"
    
    # Hitung jumlah alamat pengirim (korban) yang unik
    unique_victims = incoming_txs['source_address'].nunique()
    
    is_satisfied = unique_victims >= MIN_UNIQUE_VICTIMS
    explanation = f"Jumlah Korban Unik: {unique_victims} (Threshold: >= {MIN_UNIQUE_VICTIMS})"
    
    log_info(f"Heuristik 1: {'✓' if is_satisfied else '✗'} - {explanation}")
    return is_satisfied, unique_victims, explanation

def analyze_fast_consolidation_pattern(df: pd.DataFrame, target_address: str) -> Tuple[bool, float, str]:
    """
    Heuristik 2: Menganalisis pola konsolidasi cepat.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat target yang dianalisis
        
    Returns:
        Tuple[bool, float, str]: (terpenuhi, jam_konsolidasi, penjelasan)
    """
    log_info("Menganalisis Heuristik 2: Pola Konsolidasi Cepat...")
    
    # Filter transaksi masuk
    incoming_txs = df[df['destination_address'] == target_address]
    # Filter transaksi keluar
    outgoing_txs = df[df['source_address'] == target_address]
    
    if incoming_txs.empty:
        return False, float('inf'), "Tidak ada transaksi masuk"
    
    if outgoing_txs.empty:
        return False, float('inf'), "Tidak ada transaksi keluar (konsolidasi)"
    
    # Cari timestamp transaksi masuk paling awal
    earliest_incoming = incoming_txs['timestamp_utc'].min()
    
    # Cari timestamp transaksi keluar paling awal setelah transaksi masuk
    earliest_outgoing = outgoing_txs[
        outgoing_txs['timestamp_utc'] >= earliest_incoming
    ]['timestamp_utc'].min()
    
    if pd.isna(earliest_outgoing):
        return False, float('inf'), "Tidak ada transaksi keluar setelah transaksi masuk pertama"
    
    # Hitung selisih waktu dalam jam
    time_diff = (earliest_outgoing - earliest_incoming).total_seconds() / 3600
    
    is_satisfied = time_diff <= MAX_CONSOLIDATION_DELAY_HOURS
    explanation = f"Waktu Menuju Konsolidasi Pertama: {time_diff:.1f} jam (Threshold: <= {MAX_CONSOLIDATION_DELAY_HOURS} jam)"
    
    log_info(f"Heuristik 2: {'✓' if is_satisfied else '✗'} - {explanation}")
    return is_satisfied, time_diff, explanation

def analyze_asset_diversity_pattern(df: pd.DataFrame, target_address: str) -> Tuple[bool, int, str]:
    """
    Heuristik 3: Menganalisis diversitas aset.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat target yang dianalisis
        
    Returns:
        Tuple[bool, int, str]: (terpenuhi, jumlah_aset_unik, penjelasan)
    """
    log_info("Menganalisis Heuristik 3: Diversitas Aset...")
    
    # Filter transaksi masuk ke alamat target
    incoming_txs = df[df['destination_address'] == target_address]
    
    if incoming_txs.empty:
        return False, 0, "Tidak ada transaksi masuk ke alamat target"
    
    # Hitung jumlah token mint address yang unik
    unique_assets = incoming_txs['token_mint_address'].nunique()
    
    is_satisfied = unique_assets >= MIN_ASSET_DIVERSITY
    explanation = f"Jumlah Jenis Aset Unik: {unique_assets} (Threshold: >= {MIN_ASSET_DIVERSITY})"
    
    log_info(f"Heuristik 3: {'✓' if is_satisfied else '✗'} - {explanation}")
    return is_satisfied, unique_assets, explanation

# =============================================================================
# FUNGSI KLASIFIKASI TIPOLOGI SERANGAN
# =============================================================================

def classify_attack_typology(df: pd.DataFrame, target_address: str, heuristic_results: Dict[str, Any]) -> str:
    """
    Mengklasifikasikan tipologi serangan berdasarkan pola transaksi.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat drainer
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        
    Returns:
        str: Tipologi serangan yang teridentifikasi
    """
    log_info("Melakukan klasifikasi tipologi serangan...")
    
    # Ambil data untuk analisis klasifikasi
    unique_victims = heuristic_results['heuristic_1']['value']
    unique_assets = heuristic_results['heuristic_3']['value']
    
    # Hitung jumlah alamat tujuan transaksi keluar yang unik
    outgoing_txs = df[df['source_address'] == target_address]
    unique_outgoing_addresses = outgoing_txs['destination_address'].nunique()
    
    # Logika klasifikasi dengan prioritas
    typologies = []
    
    # 1. Mass Drainer Attack - prioritas tinggi
    if unique_victims >= MASS_DRAINER_VICTIM_THRESHOLD:
        typologies.append("Mass Drainer Attack")
    
    # 2. Sophisticated Laundering - berdasarkan pola distribusi keluar
    if unique_outgoing_addresses >= SOPHISTICATED_LAUNDERING_OUTGOING_THRESHOLD:
        typologies.append("Sophisticated Laundering")
    
    # 3. Multi-Vector Attack - berdasarkan diversitas aset yang sangat tinggi
    if unique_assets >= MULTI_VECTOR_UNIQUE_ASSETS_THRESHOLD:
        typologies.append("Multi-Vector Attack")
    
    # Tentukan tipologi final
    if len(typologies) > 1:
        # Jika terdapat multiple indikator, gabungkan
        attack_typology = " + ".join(typologies)
    elif len(typologies) == 1:
        attack_typology = typologies[0]
    else:
        attack_typology = "General Drainer Attack"
    
    log_info(f"Tipologi serangan teridentifikasi: {attack_typology}")
    
    # Log detail untuk debugging
    log_info(f"Detail klasifikasi:")
    log_info(f"  - Unique Victims: {unique_victims} (Mass threshold: {MASS_DRAINER_VICTIM_THRESHOLD})")
    log_info(f"  - Unique Outgoing Addresses: {unique_outgoing_addresses} (Laundering threshold: {SOPHISTICATED_LAUNDERING_OUTGOING_THRESHOLD})")
    log_info(f"  - Unique Assets: {unique_assets} (Multi-vector threshold: {MULTI_VECTOR_UNIQUE_ASSETS_THRESHOLD})")
    
    return attack_typology

# =============================================================================
# FUNGSI GENERASI GRAF JSON
# =============================================================================

def generate_graph_data(df: pd.DataFrame, target_address: str, attack_typology: str) -> Dict[str, Any]:
    """
    Menghasilkan data graf dalam format JSON untuk visualisasi 3D.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat drainer yang menjadi pusat graf
        attack_typology (str): Tipologi serangan yang teridentifikasi
        
    Returns:
        Dict[str, Any]: Data graf dalam format yang sesuai untuk library 3D
    """
    log_info("Menghasilkan data graf untuk visualisasi 3D...")
    
    # Kumpulkan semua alamat unik yang terlibat dalam transaksi
    all_addresses = set()
    all_addresses.update(df['source_address'].unique())
    all_addresses.update(df['destination_address'].unique())
    
    # Buat nodes
    nodes = []
    for i, address in enumerate(all_addresses):
        # Hitung total transaksi untuk alamat ini
        incoming_count = len(df[df['destination_address'] == address])
        outgoing_count = len(df[df['source_address'] == address])
        total_transactions = incoming_count + outgoing_count
        
        # Tentukan tipe node
        if address == target_address:
            node_type = "drainer"
            node_name = f"DRAINER ({address[:8]}...)"
            node_val = max(50, total_transactions)  # Nilai minimum untuk drainer
        else:
            # Cek apakah ini victim (mengirim ke drainer)
            is_victim = len(df[(df['source_address'] == address) & 
                              (df['destination_address'] == target_address)]) > 0
            if is_victim:
                node_type = "victim"
                node_name = f"VICTIM ({address[:8]}...)"
                node_val = max(5, total_transactions)
            else:
                node_type = "other"
                node_name = f"OTHER ({address[:8]}...)"
                node_val = max(1, total_transactions)
        
        nodes.append({
            "id": address,
            "name": node_name,
            "val": node_val,
            "type": node_type,
            "incoming_count": incoming_count,
            "outgoing_count": outgoing_count
        })
    
    # Buat links berdasarkan transaksi
    links = []
    transaction_pairs = df.groupby(['source_address', 'destination_address']).agg({
        'amount': 'sum',
        'tx_hash': 'count'
    }).reset_index()
    
    for _, row in transaction_pairs.iterrows():
        source = row['source_address']
        target = row['destination_address']
        total_amount = row['amount']
        tx_count = row['tx_hash']
        
        links.append({
            "source": source,
            "target": target,
            "value": tx_count,  # Jumlah transaksi sebagai weight
            "total_amount": float(total_amount) if pd.notna(total_amount) else 0
        })
    
    graph_data = {
        "nodes": nodes,
        "links": links,
        "metadata": {
            "drainer_address": target_address,
            "attack_typology": attack_typology,
            "total_nodes": len(nodes),
            "total_links": len(links),
            "generated_at": datetime.now().isoformat()
        }
    }
    
    log_info(f"Graf berhasil dibuat: {len(nodes)} nodes, {len(links)} links")
    return graph_data

def save_graph_json(graph_data: Dict[str, Any], target_address: str) -> str:
    """
    Menyimpan data graf ke file JSON.
    
    Args:
        graph_data (Dict[str, Any]): Data graf yang akan disimpan
        target_address (str): Alamat drainer untuk nama file
        
    Returns:
        str: Path file JSON yang telah disimpan
    """
    # Buat nama file dari alamat (ambil 8 karakter pertama)
    filename = f"{target_address[:8]}.json"
    filepath = os.path.join(os.getcwd(), filename)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        
        log_info(f"File graf JSON berhasil disimpan: {filepath}")
        return filepath
        
    except Exception as e:
        log_info(f"Error saat menyimpan file JSON: {e}")
        raise

# =============================================================================
# FUNGSI ANALISIS UTAMA
# =============================================================================

def perform_heuristic_analysis(df: pd.DataFrame, target_address: str, csv_file: str) -> Dict[str, Any]:
    """
    Melakukan analisis lengkap berdasarkan ketiga heuristik.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat target yang dianalisis
        csv_file (str): Nama file CSV sumber data
        
    Returns:
        Dict[str, Any]: Hasil analisis lengkap
    """
    log_info(f"Memulai analisis heuristik untuk alamat: {target_address}")
    
    # Jalankan ketiga heuristik
    h1_satisfied, h1_value, h1_explanation = analyze_massive_reception_pattern(df, target_address)
    h2_satisfied, h2_value, h2_explanation = analyze_fast_consolidation_pattern(df, target_address)
    h3_satisfied, h3_value, h3_explanation = analyze_asset_diversity_pattern(df, target_address)
    
    # Hitung skor total
    total_satisfied = sum([h1_satisfied, h2_satisfied, h3_satisfied])
    
    # Tentukan kesimpulan
    is_drainer = total_satisfied >= 2  # Minimal 2 dari 3 kriteria terpenuhi
    
    result = {
        'address': target_address,
        'csv_file': csv_file,
        'heuristic_1': {
            'satisfied': h1_satisfied,
            'value': h1_value,
            'explanation': h1_explanation
        },
        'heuristic_2': {
            'satisfied': h2_satisfied,
            'value': h2_value,
            'explanation': h2_explanation
        },
        'heuristic_3': {
            'satisfied': h3_satisfied,
            'value': h3_value,
            'explanation': h3_explanation
        },
        'total_satisfied': total_satisfied,
        'is_drainer': is_drainer
    }
    
    return result

def print_analysis_report(result: Dict[str, Any]) -> None:
    """
    Mencetak laporan hasil analisis dalam format yang rapi.
    
    Args:
        result (Dict[str, Any]): Hasil analisis dari perform_heuristic_analysis
    """
    print("\n" + "="*60)
    print("📊 LAPORAN VALIDASI HEURISTIK DRAIN WALLET")
    print("="*60)
    print(f"Alamat Target: {result['address']}")
    print(f"Sumber Data  : {result['csv_file']}")
    print("\n" + "-"*60)
    
    # Heuristik 1
    h1 = result['heuristic_1']
    status_1 = "✓" if h1['satisfied'] else "✗"
    print(f"[{status_1}] Heuristik 1: Pola Penerimaan Masif")
    print(f"    - {h1['explanation']}")
    print()
    
    # Heuristik 2
    h2 = result['heuristic_2']
    status_2 = "✓" if h2['satisfied'] else "✗"
    print(f"[{status_2}] Heuristik 2: Pola Konsolidasi Cepat")
    print(f"    - {h2['explanation']}")
    print()
    
    # Heuristik 3
    h3 = result['heuristic_3']
    status_3 = "✓" if h3['satisfied'] else "✗"
    print(f"[{status_3}] Heuristik 3: Diversitas Aset")
    print(f"    - {h3['explanation']}")
    print()
    
    # Kesimpulan
    print("-"*60)
    print("🎯 KESIMPULAN")
    print("-"*60)
    
    conclusion = "MEMENUHI SYARAT" if result['is_drainer'] else "TIDAK MEMENUHI SYARAT"
    satisfied_count = result['total_satisfied']
    
    print(f"Alamat ini {conclusion} sebagai Drain Wallet")
    print(f"({satisfied_count} dari 3 kriteria terpenuhi)")
    
    # Tampilkan tipologi serangan jika ada
    if result['is_drainer'] and 'attack_typology' in result:
        print(f"Tipologi Serangan Teridentifikasi: {result['attack_typology']}")
    
    if result['is_drainer']:
        print("\n⚠️  REKOMENDASI: Alamat ini menunjukkan pola yang konsisten dengan")
        print("   aktivitas drain wallet dan layak untuk investigasi lebih lanjut.")
    else:
        print("\n✅ REKOMENDASI: Alamat ini tidak menunjukkan pola yang konsisten")
        print("   dengan aktivitas drain wallet berdasarkan kriteria yang dianalisis.")
    
    print("="*60)

# =============================================================================
# FUNGSI UTAMA
# =============================================================================

def main():
    """
    Fungsi utama program.
    """
    parser = argparse.ArgumentParser(
        description="Analisis heuristik untuk validasi drain wallet dengan klasifikasi tipologi serangan"
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path ke file CSV yang akan dianalisis"
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Alamat target (drainer) yang menjadi subjek analisis"
    )
    
    args = parser.parse_args()
    
    try:
        # Load dan preprocess data
        df = load_transaction_data(args.file)
        
        # Jalankan analisis heuristik
        result = perform_heuristic_analysis(df, args.address, args.file)
        
        # Jika validasi drainer terpenuhi, lakukan klasifikasi tipologi
        if result['is_drainer']:
            attack_typology = classify_attack_typology(df, args.address, result)
            result['attack_typology'] = attack_typology
        
        # Tampilkan laporan
        print_analysis_report(result)
        
        # Jika validasi drainer terpenuhi, generate dan simpan file JSON
        if result['is_drainer']:
            log_info("Validasi drainer terpenuhi! Membuat file graf JSON...")
            
            # Generate data graf dengan tipologi serangan
            graph_data = generate_graph_data(df, args.address, result['attack_typology'])
            
            # Simpan ke file JSON
            json_filepath = save_graph_json(graph_data, args.address)
            
            print("\n" + "="*60)
            print("🎯 FILE GRAF JSON TELAH DIBUAT")
            print("="*60)
            print(f"📁 File Path: {json_filepath}")
            print(f"🏷️  Attack Typology: {graph_data['metadata']['attack_typology']}")
            print(f"📊 Total Nodes: {graph_data['metadata']['total_nodes']}")
            print(f"🔗 Total Links: {graph_data['metadata']['total_links']}")
            print(f"⏰ Generated At: {graph_data['metadata']['generated_at']}")
            print("\n💡 File ini dapat digunakan untuk visualisasi 3D graf transaksi.")
            print("="*60)
        
        log_info("Analisis selesai!")
        
    except Exception as e:
        log_info(f"ERROR: {e}")
        return

if __name__ == "__main__":
    main()