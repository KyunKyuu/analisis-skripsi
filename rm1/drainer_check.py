#!/usr/bin/env python3
"""
drainer_heuristic_validator.py

Script untuk menganalisis data transaksi dan memvalidasi apakah alamat memenuhi
kriteria heuristik sebagai drain wallet.

Author: Expert Python Developer
Purpose: RM 1 - Analisis Pola Transaksi Drain Wallet
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
MAX_CONSOLIDATION_DELAY_HOURS = 0.40

# Heuristik 3: Diversitas Aset
MIN_ASSET_DIVERSITY = 3

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
# FUNGSI PERHITUNGAN METRIK BERBASIS DATA
# =============================================================================

def calculate_all_metrics(df: pd.DataFrame, drainer_address: str) -> Dict[str, Any]:
    """
    Menghitung semua metrik kuantitatif berdasarkan data transaksi aktual.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        drainer_address (str): Alamat drainer yang dianalisis
        
    Returns:
        Dict[str, Any]: Dictionary berisi semua metrik yang dihitung dari data
    """
    log_info("Menghitung metrik kuantitatif dari data transaksi...")
    
    # Filter transaksi masuk ke drainer
    incoming_txs = df[df['destination_address'] == drainer_address]
    
    # 1. Total Korban Terdampak
    total_victims = incoming_txs['source_address'].nunique()
    log_info(f"Total korban terdampak: {total_victims}")
    
    # 2. Indeks Ledakan Transaksi (Burst Index)
    burst_index = 0
    if not incoming_txs.empty:
        # Pastikan timestamp dalam format datetime
        incoming_txs_copy = incoming_txs.copy()
        incoming_txs_copy['hour_floor'] = incoming_txs_copy['timestamp_utc'].dt.floor('H')
        
        # Kelompokkan per jam dan hitung korban unik per jam
        hourly_victims = incoming_txs_copy.groupby('hour_floor')['source_address'].nunique()
        burst_index = hourly_victims.max() if not hourly_victims.empty else 0
    
    log_info(f"Indeks ledakan transaksi: {burst_index}")
    
    # 3. Estimasi Kerugian SOL & USDC
    total_sol_stolen = 0.0
    total_usdc_stolen = 0.0
    
    if not incoming_txs.empty:
        # SOL Native Transfer
        sol_txs = incoming_txs[
            (incoming_txs['transaction_type'] == 'NATIVE_TRANSFER') |
            (incoming_txs['transaction_type'] == 'SOL_TRANSFER') |
            (incoming_txs['token_mint_address'].isna()) |
            (incoming_txs['token_mint_address'] == '') |
            (incoming_txs['token_mint_address'] == 'So11111111111111111111111111111111111111112')
        ]
        total_sol_stolen = sol_txs['amount'].sum()
        
        # USDC Transfer (alamat mint USDC di Solana)
        usdc_mint_addresses = [
            'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',  # USDC
            'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',  # USDT (juga dihitung sebagai stablecoin)
        ]
        
        usdc_txs = incoming_txs[incoming_txs['token_mint_address'].isin(usdc_mint_addresses)]
        total_usdc_stolen = usdc_txs['amount'].sum()
    
    log_info(f"Total SOL dicuri: {total_sol_stolen:.6f}")
    log_info(f"Total USDC/Stablecoin dicuri: {total_usdc_stolen:.2f}")
    
    # 4. Diversitas Aset
    asset_diversity = incoming_txs['token_mint_address'].nunique() if not incoming_txs.empty else 0
    log_info(f"Diversitas aset: {asset_diversity}")
    
    # 5. Total Aliran Dana & Node
    total_links = len(df)  # Total transaksi
    
    # Hitung total alamat unik (nodes)
    all_addresses = set()
    all_addresses.update(df['source_address'].unique())
    all_addresses.update(df['destination_address'].unique())
    total_nodes = len(all_addresses)
    
    log_info(f"Total links (transaksi): {total_links}")
    log_info(f"Total nodes (alamat unik): {total_nodes}")
    
    return {
        'total_victims': total_victims,
        'burst_index': burst_index,
        'total_sol_stolen': float(total_sol_stolen),
        'total_usdc_stolen': float(total_usdc_stolen),
        'asset_diversity': asset_diversity,
        'total_links': total_links,
        'total_nodes': total_nodes
    }

# =============================================================================
# FUNGSI GENERASI GRAF JSON
# =============================================================================

def generate_graph_data(df: pd.DataFrame, target_address: str, heuristic_results: Dict[str, Any] = None, metrics: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Menghasilkan data graf dalam format JSON untuk visualisasi 3D.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        target_address (str): Alamat drainer yang menjadi pusat graf
        heuristic_results (Dict[str, Any], optional): Hasil analisis heuristik untuk menentukan tipologi serangan
        metrics (Dict[str, Any], optional): Metrik kuantitatif yang dihitung dari data
        
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
            "val": int(node_val),
            "type": node_type,
            "incoming_count": int(incoming_count),
            "outgoing_count": int(outgoing_count)
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
            "value": int(tx_count),  # Jumlah transaksi sebagai weight
            "total_amount": float(total_amount) if pd.notna(total_amount) else 0.0
        })
    
    # Tentukan tipologi serangan berdasarkan hasil heuristik
    attack_typology = "Unknown Attack Pattern"
    if heuristic_results is not None:
        attack_typology = determine_attack_typology(heuristic_results)
    
    # Buat metadata yang kaya dengan data kuantitatif
    metadata = {
        "drainer_address": target_address,
        "attack_typology": attack_typology,
        "generated_at": datetime.now().isoformat()
    }
    
    # Tambahkan metrik kuantitatif jika tersedia
    if metrics is not None:
        metadata.update({
            "total_victims": metrics['total_victims'],
            "burst_index": metrics['burst_index'],
            "total_sol_stolen": metrics['total_sol_stolen'],
            "total_usdc_stolen": metrics['total_usdc_stolen'],
            "asset_diversity": metrics['asset_diversity'],
            "total_links": metrics['total_links'],
            "total_nodes": metrics['total_nodes']
        })
    else:
        # Fallback ke perhitungan sederhana jika metrics tidak tersedia
        metadata.update({
            "total_nodes": len(nodes),
            "total_links": len(links)
        })
    
    graph_data = {
        "nodes": nodes,
        "links": links,
        "metadata": metadata
    }
    
    log_info(f"Graf berhasil dibuat: {len(nodes)} nodes, {len(links)} links")
    return graph_data

def determine_attack_typology(heuristic_results: Dict[str, Any]) -> str:
    """
    Menentukan tipologi serangan berdasarkan hasil analisis heuristik.
    
    Args:
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        
    Returns:
        str: Tipologi serangan yang terdeteksi
    """
    typologies = []
    
    # Cek Mass Drainer Attack (Heuristik 1: Massive Reception Pattern)
    if heuristic_results['heuristic_1']['satisfied']:
        typologies.append("Mass Drainer Attack")
    
    # Cek Sophisticated Laundering (Heuristik 2: Fast Consolidation Pattern)
    if heuristic_results['heuristic_2']['satisfied']:
        typologies.append("Sophisticated Laundering")
    
    # Cek Multi-Vector Attack (Heuristik 3: Asset Diversity Pattern)
    if heuristic_results['heuristic_3']['satisfied']:
        typologies.append("Multi-Vector Attack")
    
    # Gabungkan tipologi dengan " + " jika lebih dari satu
    if len(typologies) == 0:
        return "Unknown Attack Pattern"
    elif len(typologies) == 1:
        return typologies[0]
    else:
        return " + ".join(typologies)

def convert_to_json_serializable(obj):
    """
    Mengkonversi objek pandas/numpy ke tipe data yang bisa di-serialize ke JSON.
    
    Args:
        obj: Objek yang akan dikonversi
        
    Returns:
        Objek yang bisa di-serialize ke JSON
    """
    if isinstance(obj, (np.integer, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_to_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    else:
        return obj

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
        # Konversi data ke format yang aman untuk JSON
        safe_graph_data = convert_to_json_serializable(graph_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(safe_graph_data, f, indent=2, ensure_ascii=False)
        
        log_info(f"File graf JSON berhasil disimpan: {filepath}")
        return filepath
        
    except Exception as e:
        log_info(f"Error saat menyimpan file JSON: {e}")
        raise

# =============================================================================
# FUNGSI PERHITUNGAN METRIK KUANTITATIF
# =============================================================================

def calculate_all_metrics(df: pd.DataFrame, drainer_address: str) -> Dict[str, Any]:
    """
    Menghitung semua metrik kuantitatif berdasarkan data transaksi aktual.
    
    Args:
        df (pd.DataFrame): DataFrame transaksi
        drainer_address (str): Alamat drainer yang dianalisis
        
    Returns:
        Dict[str, Any]: Dictionary berisi semua metrik kuantitatif
    """
    log_info("Menghitung metrik kuantitatif dari data transaksi...")
    
    # Filter transaksi yang masuk ke drainer
    incoming_to_drainer = df[df['destination_address'] == drainer_address].copy()
    
    # 1. Total Korban Terdampak
    total_victims = incoming_to_drainer['source_address'].nunique()
    log_info(f"Total korban terdampak: {total_victims}")
    
    # 2. Indeks Ledakan Transaksi
    burst_index = 0
    if not incoming_to_drainer.empty and 'timestamp_utc' in incoming_to_drainer.columns:
        # Pastikan timestamp dalam format datetime
        if not pd.api.types.is_datetime64_any_dtype(incoming_to_drainer['timestamp_utc']):
            incoming_to_drainer['timestamp_utc'] = pd.to_datetime(incoming_to_drainer['timestamp_utc'])
        
        # Kelompokkan per jam dan hitung korban unik per jam
        hourly_victims = (incoming_to_drainer
                         .groupby(incoming_to_drainer['timestamp_utc'].dt.floor('h'))
                         ['source_address']
                         .nunique())
        
        if not hourly_victims.empty:
            burst_index = hourly_victims.max()
    
    log_info(f"Indeks ledakan transaksi: {burst_index}")
    
    # 3. Estimasi Kerugian SOL
    total_sol_stolen = 0.0
    sol_transactions = incoming_to_drainer[
        (incoming_to_drainer['transaction_type'] == 'NATIVE_TRANSFER') |
        (incoming_to_drainer['token_mint_address'].isna()) |
        (incoming_to_drainer['token_mint_address'] == '') |
        (incoming_to_drainer['token_mint_address'] == 'So11111111111111111111111111111111111111112')  # Wrapped SOL
    ]
    
    if not sol_transactions.empty and 'amount' in sol_transactions.columns:
        total_sol_stolen = sol_transactions['amount'].sum()
    
    log_info(f"Total SOL yang dicuri: {total_sol_stolen:.6f}")
    
    # 4. Estimasi Kerugian USDC
    total_usdc_stolen = 0.0
    # USDC mint address di Solana
    usdc_mint_addresses = [
        'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',  # USDC
        'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'   # USDT (juga dihitung sebagai stablecoin)
    ]
    
    usdc_transactions = incoming_to_drainer[
        incoming_to_drainer['token_mint_address'].isin(usdc_mint_addresses)
    ]
    
    if not usdc_transactions.empty and 'amount' in usdc_transactions.columns:
        total_usdc_stolen = usdc_transactions['amount'].sum()
    
    log_info(f"Total USDC/USDT yang dicuri: {total_usdc_stolen:.2f}")
    
    # 5. Diversitas Aset
    asset_diversity = 0
    if 'token_mint_address' in incoming_to_drainer.columns:
        # Hitung token unik, termasuk SOL native
        unique_tokens = set()
        
        # Tambahkan SOL native jika ada transaksi native
        if len(sol_transactions) > 0:
            unique_tokens.add('SOL_NATIVE')
        
        # Tambahkan token mint addresses yang tidak kosong
        token_mints = incoming_to_drainer['token_mint_address'].dropna()
        token_mints = token_mints[token_mints != '']
        unique_tokens.update(token_mints.unique())
        
        asset_diversity = len(unique_tokens)
    
    log_info(f"Diversitas aset: {asset_diversity}")
    
    # 6. Total Aliran Dana & Node
    total_links = len(df)
    
    # Hitung total alamat unik
    all_addresses = set()
    all_addresses.update(df['source_address'].unique())
    all_addresses.update(df['destination_address'].unique())
    total_nodes = len(all_addresses)
    
    log_info(f"Total links (transaksi): {total_links}")
    log_info(f"Total nodes (alamat unik): {total_nodes}")
    
    # Kembalikan semua metrik dengan konversi tipe data yang aman untuk JSON
    metrics = {
        'total_victims': int(total_victims),
        'burst_index': int(burst_index),
        'total_sol_stolen': float(total_sol_stolen),
        'total_usdc_stolen': float(total_usdc_stolen),
        'asset_diversity': int(asset_diversity),
        'total_links': int(total_links),
        'total_nodes': int(total_nodes)
    }
    
    log_info("Perhitungan metrik kuantitatif selesai!")
    return metrics

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
        description="Analisis heuristik untuk validasi drain wallet"
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
        
        # Tampilkan laporan
        print_analysis_report(result)
        
        # Jika validasi drainer terpenuhi, generate dan simpan file JSON
        if result['is_drainer']:
            log_info("Validasi drainer terpenuhi! Membuat file graf JSON...")
            
            # Hitung semua metrik kuantitatif dari data
            metrics = calculate_all_metrics(df, args.address)
            
            # Generate data graf dengan hasil heuristik dan metrik
            graph_data = generate_graph_data(df, args.address, result, metrics)
            
            # Simpan ke file JSON
            json_filepath = save_graph_json(graph_data, args.address)
            
            print("\n" + "="*60)
            print("🎯 FILE GRAF JSON TELAH DIBUAT")
            print("="*60)
            print(f"📁 File Path: {json_filepath}")
            print(f"🏷️ Attack Typology: {graph_data['metadata']['attack_typology']}")
            print(f"👥 Total Victims: {graph_data['metadata'].get('total_victims', 'N/A')}")
            print(f"💥 Burst Index: {graph_data['metadata'].get('burst_index', 'N/A')}")
            print(f"🪙 SOL Stolen: {graph_data['metadata'].get('total_sol_stolen', 0):.6f}")
            print(f"💰 USDC Stolen: {graph_data['metadata'].get('total_usdc_stolen', 0):.2f}")
            print(f"🎯 Asset Diversity: {graph_data['metadata'].get('asset_diversity', 'N/A')}")
            print(f"📊 Total Nodes: {graph_data['metadata']['total_nodes']}")
            print(f"🔗 Total Links: {graph_data['metadata']['total_links']}")
            print(f"⏰ Generated At: {graph_data['metadata']['generated_at']}")
            print("\n💡 File ini berisi data kuantitatif lengkap untuk visualisasi 3D graf transaksi.")
            print("="*60)
        
        log_info("Analisis selesai!")
        
    except Exception as e:
        log_info(f"ERROR: {e}")
        return

if __name__ == "__main__":
    main()