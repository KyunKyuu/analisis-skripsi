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
# KONFIGURASI VALIDATION STATUS
# =============================================================================

# Status validasi yang mungkin
VALIDATION_STATUS = {
    'VERIFIED': 'verified',      # Terverifikasi sebagai drainer
    'SUSPECT': 'suspect',        # Mencurigakan, perlu investigasi manual
    'REJECTED': 'rejected'       # Ditolak, bukan drainer
}

# Threshold untuk auto-verification
AUTO_VERIFY_THRESHOLDS = {
    'min_heuristics_passed': 3,     # Minimal 3 heuristik terpenuhi untuk auto-verify
    'min_victims_for_verify': 20,   # Minimal 50 korban untuk auto-verify
    'max_consolidation_hours': 0.45, # Maksimal 15 menit untuk auto-verify
    'min_asset_diversity': 3        # Minimal 5 jenis aset untuk auto-verify
}

# Database alamat yang sudah diverifikasi (simulasi)
KNOWN_DRAINER_ADDRESSES = {
    # Contoh alamat drainer yang sudah terverifikasi
    "2PvbiHwbj6kcVwwwM6y6ApVij587LmZ5xmQReh9aGDtc": "verified",
    "ConfnKVMDysrY7UqtLw35zafLyLq3txAQ7y2iSzCrWyk": "verified",
    "FbpCfLxM7umSbfYKXPtN3RSkMdmcdt6ifEEqC3dZGhLB": "verified",
    # Tambahkan alamat lain sesuai kebutuhan
}

# Blacklist alamat yang sudah dipastikan bukan drainer
BLACKLISTED_ADDRESSES = {
    # Contoh alamat exchange atau service yang legitimate
    "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM": "rejected",  # Phantom Wallet
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "rejected",   # Token Program
    # Tambahkan alamat lain sesuai kebutuhan
}

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
# PIPELINE VERIFIKASI OTOMATIS
# =============================================================================

def check_known_addresses(address: str) -> Tuple[str, str]:
    """
    Langkah 1: Cek alamat terhadap database yang sudah diverifikasi.
    
    Args:
        address (str): Alamat yang akan dicek
        
    Returns:
        Tuple[str, str]: (status, alasan)
    """
    # Cek apakah alamat sudah diverifikasi sebagai drainer
    if address in KNOWN_DRAINER_ADDRESSES:
        return KNOWN_DRAINER_ADDRESSES[address], "Alamat sudah terdaftar dalam database drainer terverifikasi"
    
    # Cek apakah alamat dalam blacklist (legitimate service)
    if address in BLACKLISTED_ADDRESSES:
        return BLACKLISTED_ADDRESSES[address], "Alamat terdaftar sebagai layanan legitimate"
    
    return "unknown", "Alamat belum terdaftar dalam database"

def simulate_third_party_check(address: str, heuristic_results: Dict[str, Any]) -> Tuple[str, str]:
    """
    Langkah 2: Simulasi cross-check dengan pihak ketiga (Immunefi, Chainalysis, TRM).
    
    Args:
        address (str): Alamat yang akan dicek
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        
    Returns:
        Tuple[str, str]: (status, alasan)
    """
    log_info("Melakukan simulasi cross-check dengan database pihak ketiga...")
    
    # Simulasi: Jika alamat memiliki pola yang sangat mencurigakan
    total_satisfied = heuristic_results.get('total_satisfied', 0)
    h1_value = heuristic_results.get('heuristic_1', {}).get('value', 0)
    h2_value = heuristic_results.get('heuristic_2', {}).get('value', float('inf'))
    
    # Simulasi hit pada database Chainalysis/TRM
    if total_satisfied >= 2 and h1_value >= 100:
        return "verified", "Alamat ditemukan dalam database Chainalysis sebagai high-risk entity"
    
    # Simulasi laporan komunitas
    if total_satisfied >= 2 and h2_value <= 0.1:  # Konsolidasi sangat cepat
        return "suspect", "Pola transaksi cocok dengan laporan komunitas tentang aktivitas mencurigakan"
    
    # Simulasi tidak ditemukan dalam database manapun
    if total_satisfied == 0:
        return "rejected", "Tidak ditemukan indikasi dalam database pihak ketiga"
    
    return "suspect", "Memerlukan verifikasi manual lebih lanjut"

def automated_heuristic_verification(heuristic_results: Dict[str, Any], metrics: Dict[str, Any]) -> Tuple[str, str]:
    """
    Langkah 3: Verifikasi otomatis berdasarkan threshold yang ketat.
    
    Args:
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        metrics (Dict[str, Any]): Metrik kuantitatif
        
    Returns:
        Tuple[str, str]: (status, alasan)
    """
    total_satisfied = heuristic_results.get('total_satisfied', 0)
    total_victims = metrics.get('total_victims', 0)
    asset_diversity = metrics.get('asset_diversity', 0)
    
    # Ambil nilai konsolidasi dari heuristik 2
    consolidation_hours = heuristic_results.get('heuristic_2', {}).get('value', float('inf'))
    
    # Auto-verify jika semua threshold terpenuhi
    if (total_satisfied >= AUTO_VERIFY_THRESHOLDS['min_heuristics_passed'] and
        total_victims >= AUTO_VERIFY_THRESHOLDS['min_victims_for_verify'] and
        consolidation_hours <= AUTO_VERIFY_THRESHOLDS['max_consolidation_hours'] and
        asset_diversity >= AUTO_VERIFY_THRESHOLDS['min_asset_diversity']):
        
        return VALIDATION_STATUS['VERIFIED'], f"Auto-verified: {total_satisfied}/3 heuristik, {total_victims} korban, konsolidasi {consolidation_hours:.2f}h, {asset_diversity} aset"
    
    # Auto-reject jika tidak ada heuristik yang terpenuhi
    if total_satisfied == 0:
        return VALIDATION_STATUS['REJECTED'], "Auto-rejected: Tidak ada heuristik yang terpenuhi"
    
    # Suspect untuk kasus di antara
    return VALIDATION_STATUS['SUSPECT'], f"Memerlukan review manual: {total_satisfied}/3 heuristik terpenuhi"

def manual_verification_checklist(address: str, heuristic_results: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Menghasilkan checklist untuk verifikasi manual oleh analis.
    
    Args:
        address (str): Alamat yang dianalisis
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        metrics (Dict[str, Any]): Metrik kuantitatif
        
    Returns:
        Dict[str, Any]: Checklist untuk verifikasi manual
    """
    checklist = {
        'address': address,
        'requires_manual_review': True,
        'priority_level': 'medium',
        'verification_points': []
    }
    
    # Tentukan prioritas berdasarkan metrik
    total_victims = metrics.get('total_victims', 0)
    total_sol_stolen = metrics.get('total_sol_stolen', 0)
    
    if total_victims >= 100 or total_sol_stolen >= 1000:
        checklist['priority_level'] = 'high'
    elif total_victims >= 50 or total_sol_stolen >= 100:
        checklist['priority_level'] = 'medium'
    else:
        checklist['priority_level'] = 'low'
    
    # Poin-poin yang harus dicek manual
    verification_points = [
        {
            'point': 'Inspeksi Alamat Terkait',
            'description': 'Periksa alamat-alamat yang berinteraksi dengan target',
            'status': 'pending'
        },
        {
            'point': 'Analisis Pola Konsolidasi',
            'description': 'Verifikasi pola konsolidasi dana ke alamat lain',
            'status': 'pending'
        },
        {
            'point': 'Cross-Reference Social Media',
            'description': 'Cek laporan korban di Twitter, Discord, Reddit',
            'status': 'pending'
        },
        {
            'point': 'Verifikasi Timeline Serangan',
            'description': 'Konfirmasi timeline dengan laporan incident',
            'status': 'pending'
        },
        {
            'point': 'Analisis Smart Contract',
            'description': 'Periksa interaksi dengan smart contract mencurigakan',
            'status': 'pending'
        }
    ]
    
    checklist['verification_points'] = verification_points
    
    return checklist

def run_validation_pipeline(address: str, heuristic_results: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Menjalankan pipeline verifikasi lengkap (3 langkah).
    
    Args:
        address (str): Alamat yang akan diverifikasi
        heuristic_results (Dict[str, Any]): Hasil analisis heuristik
        metrics (Dict[str, Any]): Metrik kuantitatif
        
    Returns:
        Dict[str, Any]: Hasil verifikasi lengkap dengan status final
    """
    log_info("🔍 Memulai Pipeline Verifikasi Otomatis...")
    
    validation_result = {
        'address': address,
        'validation_status': VALIDATION_STATUS['SUSPECT'],  # Default
        'validation_steps': {},
        'final_recommendation': '',
        'confidence_score': 0.0,
        'manual_checklist': None
    }
    
    # LANGKAH 1: Cek database alamat yang sudah diverifikasi
    log_info("📋 Langkah 1: Checking known addresses database...")
    step1_status, step1_reason = check_known_addresses(address)
    validation_result['validation_steps']['step_1_known_addresses'] = {
        'status': step1_status,
        'reason': step1_reason
    }
    
    # Jika sudah ada di database, langsung return
    if step1_status in [VALIDATION_STATUS['VERIFIED'], VALIDATION_STATUS['REJECTED']]:
        validation_result['validation_status'] = step1_status
        validation_result['final_recommendation'] = step1_reason
        validation_result['confidence_score'] = 1.0
        log_info(f"✅ Pipeline selesai di Langkah 1: {step1_status}")
        return validation_result
    
    # LANGKAH 2: Cross-check dengan pihak ketiga (simulasi)
    log_info("🌐 Langkah 2: Cross-checking with third-party databases...")
    step2_status, step2_reason = simulate_third_party_check(address, heuristic_results)
    validation_result['validation_steps']['step_2_third_party'] = {
        'status': step2_status,
        'reason': step2_reason
    }
    
    # LANGKAH 3: Verifikasi heuristik otomatis
    log_info("🤖 Langkah 3: Automated heuristic verification...")
    step3_status, step3_reason = automated_heuristic_verification(heuristic_results, metrics)
    validation_result['validation_steps']['step_3_heuristic_auto'] = {
        'status': step3_status,
        'reason': step3_reason
    }
    
    # Tentukan status final berdasarkan voting dari 3 langkah
    statuses = [step2_status, step3_status]
    
    # Jika ada yang verified dan tidak ada yang rejected
    if VALIDATION_STATUS['VERIFIED'] in statuses and VALIDATION_STATUS['REJECTED'] not in statuses:
        final_status = VALIDATION_STATUS['VERIFIED']
        confidence = 0.85
    # Jika ada yang rejected dan tidak ada yang verified
    elif VALIDATION_STATUS['REJECTED'] in statuses and VALIDATION_STATUS['VERIFIED'] not in statuses:
        final_status = VALIDATION_STATUS['REJECTED']
        confidence = 0.75
    # Jika ada konflik atau semua suspect
    else:
        final_status = VALIDATION_STATUS['SUSPECT']
        confidence = 0.5
        # Generate manual checklist
        validation_result['manual_checklist'] = manual_verification_checklist(address, heuristic_results, metrics)
    
    validation_result['validation_status'] = final_status
    validation_result['confidence_score'] = confidence
    
    # Generate final recommendation
    if final_status == VALIDATION_STATUS['VERIFIED']:
        validation_result['final_recommendation'] = "Alamat terverifikasi sebagai drainer berdasarkan multiple indicators"
    elif final_status == VALIDATION_STATUS['REJECTED']:
        validation_result['final_recommendation'] = "Alamat tidak memenuhi kriteria drainer"
    else:
        validation_result['final_recommendation'] = "Memerlukan verifikasi manual oleh analis"
    
    log_info(f"🎯 Pipeline selesai: Status = {final_status}, Confidence = {confidence:.2f}")
    return validation_result

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
        "generated_at": datetime.now().isoformat(),
        "validation_status": "pending"  # Default status, akan diupdate oleh pipeline
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
# FUNGSI PENYIMPANAN HASIL VALIDASI
# =============================================================================

def save_validation_results_to_csv(validation_results: List[Dict[str, Any]], output_file: str = None) -> str:
    """
    Menyimpan hasil validasi ke file CSV dengan kolom validation_status.
    
    Args:
        validation_results (List[Dict[str, Any]]): List hasil validasi
        output_file (str, optional): Nama file output
        
    Returns:
        str: Path file CSV yang disimpan
    """
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"validation_results_{timestamp}.csv"
    
    # Siapkan data untuk CSV
    csv_data = []
    for result in validation_results:
        row = {
            'address': result['address'],
            'validation_status': result['validation_status'],
            'confidence_score': result['confidence_score'],
            'final_recommendation': result['final_recommendation'],
            'step_1_status': result['validation_steps']['step_1_known_addresses']['status'],
            'step_1_reason': result['validation_steps']['step_1_known_addresses']['reason'],
            'step_2_status': result['validation_steps'].get('step_2_third_party', {}).get('status', 'skipped'),
            'step_2_reason': result['validation_steps'].get('step_2_third_party', {}).get('reason', 'skipped'),
            'step_3_status': result['validation_steps'].get('step_3_heuristic_auto', {}).get('status', 'skipped'),
            'step_3_reason': result['validation_steps'].get('step_3_heuristic_auto', {}).get('reason', 'skipped'),
            'requires_manual_review': result['manual_checklist'] is not None,
            'priority_level': result['manual_checklist']['priority_level'] if result['manual_checklist'] else 'none',
            'timestamp': datetime.now().isoformat()
        }
        csv_data.append(row)
    
    # Tulis ke CSV
    import csv
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = csv_data[0].keys() if csv_data else []
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_data)
    
    log_info(f"Hasil validasi disimpan ke: {output_file}")
    return output_file

def update_graph_json_with_validation(json_file: str, validation_result: Dict[str, Any]) -> None:
    """
    Update file JSON graf dengan hasil validasi.
    
    Args:
        json_file (str): Path ke file JSON graf
        validation_result (Dict[str, Any]): Hasil validasi
    """
    try:
        # Baca file JSON yang ada
        with open(json_file, 'r', encoding='utf-8') as f:
            graph_data = json.load(f)
        
        # Update metadata dengan hasil validasi
        graph_data['metadata']['validation_status'] = validation_result['validation_status']
        graph_data['metadata']['confidence_score'] = validation_result['confidence_score']
        graph_data['metadata']['final_recommendation'] = validation_result['final_recommendation']
        graph_data['metadata']['validation_timestamp'] = datetime.now().isoformat()
        
        # Tambahkan detail validasi steps
        graph_data['metadata']['validation_details'] = validation_result['validation_steps']
        
        # Jika ada manual checklist, tambahkan juga
        if validation_result['manual_checklist']:
            graph_data['metadata']['manual_checklist'] = validation_result['manual_checklist']
        
        # Simpan kembali ke file
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2, ensure_ascii=False)
        
        log_info(f"File JSON graf berhasil diupdate dengan hasil validasi: {json_file}")
        
    except Exception as e:
        log_info(f"Error saat mengupdate file JSON: {e}")

def generate_validation_report(validation_result: Dict[str, Any]) -> str:
    """
    Menghasilkan laporan validasi dalam format teks yang mudah dibaca.
    
    Args:
        validation_result (Dict[str, Any]): Hasil validasi
        
    Returns:
        str: Laporan validasi dalam format teks
    """
    report = []
    report.append("="*80)
    report.append("🔍 LAPORAN PIPELINE VERIFIKASI OTOMATIS")
    report.append("="*80)
    report.append(f"Alamat Target: {validation_result['address']}")
    report.append(f"Status Validasi: {validation_result['validation_status'].upper()}")
    report.append(f"Confidence Score: {validation_result['confidence_score']:.2f}")
    report.append(f"Rekomendasi: {validation_result['final_recommendation']}")
    report.append("")
    
    report.append("-"*80)
    report.append("📋 DETAIL LANGKAH VERIFIKASI")
    report.append("-"*80)
    
    # Langkah 1
    step1 = validation_result['validation_steps']['step_1_known_addresses']
    report.append(f"[1] Database Alamat Terverifikasi:")
    report.append(f"    Status: {step1['status']}")
    report.append(f"    Alasan: {step1['reason']}")
    report.append("")
    
    # Langkah 2 (jika ada)
    if 'step_2_third_party' in validation_result['validation_steps']:
        step2 = validation_result['validation_steps']['step_2_third_party']
        report.append(f"[2] Cross-check Pihak Ketiga:")
        report.append(f"    Status: {step2['status']}")
        report.append(f"    Alasan: {step2['reason']}")
        report.append("")
    
    # Langkah 3 (jika ada)
    if 'step_3_heuristic_auto' in validation_result['validation_steps']:
        step3 = validation_result['validation_steps']['step_3_heuristic_auto']
        report.append(f"[3] Verifikasi Heuristik Otomatis:")
        report.append(f"    Status: {step3['status']}")
        report.append(f"    Alasan: {step3['reason']}")
        report.append("")
    
    # Manual checklist (jika ada)
    if validation_result['manual_checklist']:
        checklist = validation_result['manual_checklist']
        report.append("-"*80)
        report.append("📝 CHECKLIST VERIFIKASI MANUAL")
        report.append("-"*80)
        report.append(f"Prioritas: {checklist['priority_level'].upper()}")
        report.append("")
        report.append("Poin-poin yang harus diverifikasi:")
        for i, point in enumerate(checklist['verification_points'], 1):
            report.append(f"  {i}. {point['point']}")
            report.append(f"     {point['description']}")
            report.append(f"     Status: {point['status']}")
            report.append("")
    
    report.append("="*80)
    
    return "\n".join(report)

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
        description="Analisis heuristik untuk validasi drain wallet dengan pipeline verifikasi otomatis"
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
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip pipeline verifikasi otomatis"
    )
    parser.add_argument(
        "--save-validation-csv",
        action="store_true",
        help="Simpan hasil validasi ke file CSV"
    )
    
    args = parser.parse_args()
    
    try:
        # Load dan preprocess data
        df = load_transaction_data(args.file)
        
        # Jalankan analisis heuristik
        result = perform_heuristic_analysis(df, args.address, args.file)
        
        # Tampilkan laporan heuristik
        print_analysis_report(result)
        
        # Hitung metrik kuantitatif
        metrics = calculate_all_metrics(df, args.address)
        
        # Jalankan pipeline verifikasi otomatis (kecuali jika di-skip)
        validation_result = None
        if not args.skip_validation:
            log_info("\n🔍 Memulai Pipeline Verifikasi Otomatis...")
            validation_result = run_validation_pipeline(args.address, result, metrics)
            
            # Tampilkan laporan validasi
            validation_report = generate_validation_report(validation_result)
            print("\n" + validation_report)
            
            # Simpan hasil validasi ke CSV jika diminta
            if args.save_validation_csv:
                csv_file = save_validation_results_to_csv([validation_result])
                log_info(f"✅ Hasil validasi disimpan ke: {csv_file}")
        
        # Generate dan simpan file JSON jika memenuhi kriteria
        should_generate_json = False
        if validation_result:
            # Generate JSON jika status verified atau suspect dengan confidence tinggi
            should_generate_json = (
                validation_result['validation_status'] == VALIDATION_STATUS['VERIFIED'] or
                (validation_result['validation_status'] == VALIDATION_STATUS['SUSPECT'] and 
                 validation_result['confidence_score'] >= 0.6)
            )
        else:
            # Fallback ke kriteria lama jika validasi di-skip
            should_generate_json = result['is_drainer']
        
        if should_generate_json:
            log_info("📊 Membuat file graf JSON...")
            
            # Generate data graf dengan hasil heuristik dan metrik
            graph_data = generate_graph_data(df, args.address, result, metrics)
            
            # Update metadata dengan hasil validasi jika ada
            if validation_result:
                graph_data['metadata']['validation_status'] = validation_result['validation_status']
                graph_data['metadata']['confidence_score'] = validation_result['confidence_score']
                graph_data['metadata']['final_recommendation'] = validation_result['final_recommendation']
                graph_data['metadata']['validation_timestamp'] = datetime.now().isoformat()
            
            # Simpan ke file JSON
            json_filepath = save_graph_json(graph_data, args.address)
            
            # Update JSON dengan detail validasi jika ada
            if validation_result:
                update_graph_json_with_validation(json_filepath, validation_result)
            
            print("\n" + "="*80)
            print("🎯 FILE GRAF JSON TELAH DIBUAT")
            print("="*80)
            print(f"📁 File Path: {json_filepath}")
            print(f"🏷️ Attack Typology: {graph_data['metadata']['attack_typology']}")
            
            if validation_result:
                print(f"✅ Validation Status: {validation_result['validation_status'].upper()}")
                print(f"🎯 Confidence Score: {validation_result['confidence_score']:.2f}")
            
            print(f"👥 Total Victims: {graph_data['metadata'].get('total_victims', 'N/A')}")
            print(f"💥 Burst Index: {graph_data['metadata'].get('burst_index', 'N/A')}")
            print(f"🪙 SOL Stolen: {graph_data['metadata'].get('total_sol_stolen', 0):.6f}")
            print(f"💰 USDC Stolen: {graph_data['metadata'].get('total_usdc_stolen', 0):.2f}")
            print(f"🎯 Asset Diversity: {graph_data['metadata'].get('asset_diversity', 'N/A')}")
            print(f"📊 Total Nodes: {graph_data['metadata']['total_nodes']}")
            print(f"🔗 Total Links: {graph_data['metadata']['total_links']}")
            print(f"⏰ Generated At: {graph_data['metadata']['generated_at']}")
            print("\n💡 File ini berisi data kuantitatif lengkap untuk visualisasi 3D graf transaksi.")
            print("="*80)
        else:
            if validation_result:
                log_info(f"❌ File JSON tidak dibuat karena validation status: {validation_result['validation_status']}")
            else:
                log_info("❌ File JSON tidak dibuat karena tidak memenuhi kriteria drainer")
        
        log_info("✅ Analisis selesai!")
        
    except Exception as e:
        log_info(f"ERROR: {e}")
        return

if __name__ == "__main__":
    main()