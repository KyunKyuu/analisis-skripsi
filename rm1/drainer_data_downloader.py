#!/usr/bin/env python3
"""
drainer_data_downloader.py

Script untuk mengunduh data transaksi dari alamat yang dicurigai sebagai drainer
menggunakan Helius API dan menyimpannya dalam format CSV.

Author: Expert Python Developer
Purpose: RM 1 - Analisis Pola Transaksi Drain Wallet
"""

import argparse
import requests
import csv
import json
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from config import HELIUS_API_KEY, HELIUS_BASE_URL

# =============================================================================
# KONFIGURASI SKRIP
# =============================================================================

# Batas maksimal transaksi yang akan diunduh
MAX_TRANSACTIONS_TO_FETCH = 10000

# Template nama file output CSV
CSV_OUTPUT_FILE_TEMPLATE = "{address}_transactions.csv"

# Batas jumlah transaksi per batch API call
BATCH_SIZE = 100

# Delay antara API calls untuk menghindari rate limiting (detik)
API_CALL_DELAY = 0.5

# Header CSV yang akan digunakan
CSV_HEADERS = [
    'tx_hash',
    'timestamp_utc', 
    'source_address',
    'destination_address',
    'amount',
    'token_mint_address',
    'transaction_type'
]

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

def validate_solana_address(address: str) -> bool:
    """
    Validasi sederhana untuk alamat Solana.
    
    Args:
        address (str): Alamat Solana yang akan divalidasi
        
    Returns:
        bool: True jika format alamat valid
    """
    # Alamat Solana umumnya terdiri dari 32-44 karakter base58
    if not address or len(address) < 32 or len(address) > 44:
        return False
    
    # Karakter yang diizinkan dalam base58
    base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(c in base58_chars for c in address)

# =============================================================================
# FUNGSI API HELIUS
# =============================================================================

def get_parsed_transactions(address: str, before: Optional[str] = None, limit: int = BATCH_SIZE) -> List[Dict[str, Any]]:
    """
    Mengambil transaksi yang sudah di-parse dari Helius API.
    
    Args:
        address (str): Alamat Solana target
        before (Optional[str]): Signature transaksi untuk paginasi
        limit (int): Jumlah transaksi per batch
        
    Returns:
        List[Dict[str, Any]]: List transaksi dari API Helius
        
    Raises:
        requests.RequestException: Jika API call gagal
    """
    url = f"{HELIUS_BASE_URL}/addresses/{address}/transactions?api-key={HELIUS_API_KEY}"
    
    params = {
        "limit": limit,
        "type": "TRANSFER"  # Fokus pada transaksi transfer
    }
    
    if before:
        params["before"] = before
    
    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # Handle both formats: direct list or wrapped in result
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "result" in data:
            return data["result"]
        else:
            log_info(f"Unexpected API response format: {type(data)}")
            return []
            
    except requests.RequestException as e:
        log_info(f"API request failed: {e}")
        raise
    except json.JSONDecodeError as e:
        log_info(f"Failed to parse JSON response: {e}")
        raise

def parse_and_extract_transfers(transaction: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Mengekstrak informasi transfer dari satu transaksi Helius.
    
    Args:
        transaction (Dict[str, Any]): Data transaksi dari Helius API
        
    Returns:
        List[Dict[str, Any]]: List transfer yang diekstrak
    """
    transfers = []
    tx_hash = transaction.get("signature", "")
    timestamp = transaction.get("timestamp", 0)
    
    # Convert timestamp ke format UTC string
    if timestamp:
        timestamp_utc = datetime.utcfromtimestamp(timestamp).isoformat() + "Z"
    else:
        timestamp_utc = ""
    
    # Ekstrak token transfers (SPL tokens)
    token_transfers = transaction.get("tokenTransfers", [])
    for transfer in token_transfers:
        from_address = transfer.get("fromUserAccount", "")
        to_address = transfer.get("toUserAccount", "")
        amount = transfer.get("tokenAmount", 0)
        mint_address = transfer.get("mint", "")
        
        if from_address and to_address and amount:
            transfers.append({
                'tx_hash': tx_hash,
                'timestamp_utc': timestamp_utc,
                'source_address': from_address,
                'destination_address': to_address,
                'amount': amount,
                'token_mint_address': mint_address,
                'transaction_type': 'TOKEN_TRANSFER'
            })
    
    # Ekstrak native transfers (SOL)
    native_transfers = transaction.get("nativeTransfers", [])
    for transfer in native_transfers:
        from_address = transfer.get("fromUserAccount", "")
        to_address = transfer.get("toUserAccount", "")
        amount = transfer.get("amount", 0)
        
        if from_address and to_address and amount:
            # Konversi dari lamports ke SOL (1 SOL = 1,000,000,000 lamports)
            sol_amount = amount / 1_000_000_000
            
            transfers.append({
                'tx_hash': tx_hash,
                'timestamp_utc': timestamp_utc,
                'source_address': from_address,
                'destination_address': to_address,
                'amount': sol_amount,
                'token_mint_address': 'So11111111111111111111111111111111111111112',  # SOL mint address
                'transaction_type': 'NATIVE_TRANSFER'
            })
    
    return transfers

# =============================================================================
# FUNGSI UTAMA
# =============================================================================

def download_transactions(address: str) -> str:
    """
    Mengunduh semua transaksi untuk alamat yang diberikan dan menyimpan ke CSV.
    
    Args:
        address (str): Alamat Solana yang akan dianalisis
        
    Returns:
        str: Nama file CSV yang berisi data transaksi
        
    Raises:
        Exception: Jika proses download gagal
    """
    log_info(f"Memulai download transaksi untuk alamat: {address}")
    
    # Validasi alamat
    if not validate_solana_address(address):
        raise ValueError(f"Format alamat Solana tidak valid: {address}")
    
    # Siapkan nama file output
    output_file = CSV_OUTPUT_FILE_TEMPLATE.format(address=address)
    
    all_transfers = []
    before_signature = None
    total_fetched = 0
    batch_count = 0
    
    try:
        while total_fetched < MAX_TRANSACTIONS_TO_FETCH:
            batch_count += 1
            log_info(f"Mengambil batch transaksi #{batch_count}...")
            
            # Hitung sisa transaksi yang perlu diambil
            remaining = MAX_TRANSACTIONS_TO_FETCH - total_fetched
            current_limit = min(BATCH_SIZE, remaining)
            
            # Ambil data dari API
            transactions = get_parsed_transactions(
                address=address, 
                before=before_signature, 
                limit=current_limit
            )
            
            if not transactions:
                log_info("Tidak ada transaksi lagi yang tersedia.")
                break
            
            # Ekstrak transfers dari setiap transaksi
            batch_transfers = []
            for transaction in transactions:
                transfers = parse_and_extract_transfers(transaction)
                batch_transfers.extend(transfers)
            
            all_transfers.extend(batch_transfers)
            total_fetched += len(transactions)
            
            # Update signature untuk paginasi berikutnya
            if transactions:
                before_signature = transactions[-1].get("signature")
            
            log_info(f"Batch #{batch_count} selesai. Total transaksi diproses: {total_fetched}")
            log_info(f"Total transfers diekstrak: {len(all_transfers)}")
            
            # Delay untuk menghindari rate limiting
            if total_fetched < MAX_TRANSACTIONS_TO_FETCH and len(transactions) == current_limit:
                time.sleep(API_CALL_DELAY)
            else:
                # Break if we got fewer transactions than requested (no more data)
                break
        
        # Simpan ke file CSV
        log_info(f"Menyimpan data ke file: {output_file}")
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(all_transfers)
        
        log_info(f"Download selesai! Total {len(all_transfers)} transfers disimpan ke {output_file}")
        return output_file
        
    except requests.RequestException as e:
        log_info(f"Error saat melakukan API call: {e}")
        raise
    except Exception as e:
        log_info(f"Error tidak terduga: {e}")
        raise

def main():
    """
    Fungsi utama program.
    """
    parser = argparse.ArgumentParser(
        description="Download transaksi dari alamat Solana menggunakan Helius API"
    )
    parser.add_argument(
        "--address",
        required=True,
        help="Alamat Solana yang akan diinvestigasi"
    )
    
    args = parser.parse_args()
    
    try:
        # Validasi API key
        if not HELIUS_API_KEY or HELIUS_API_KEY == "your_helius_api_key_here":
            log_info("ERROR: Silakan atur HELIUS_API_KEY di file config.py")
            return
        
        # Download transaksi
        output_file = download_transactions(args.address)
        log_info(f"Proses selesai. File output: {output_file}")
        
    except Exception as e:
        log_info(f"ERROR: {e}")
        return

if __name__ == "__main__":
    main()