#!/usr/bin/env python3
"""
Skrip untuk melakukan analisis forensik pada data historis Solana Mainnet
untuk mencari bukti adanya insiden nonce reuse dengan menganalisis komponen R
dari signature Ed25519.

"""

import requests
import csv
import time
import base58
import hashlib
import json
from datetime import datetime
from typing import Set, Dict, List, Optional
import sys
import os

# Import API key dari config.py
try:
    from config import HELIUS_API_KEY
except ImportError:
    print("❌ ERROR: File config.py tidak ditemukan atau HELIUS_API_KEY tidak terdefinisi")
    print("Pastikan file config.py berisi: HELIUS_API_KEY = 'your_api_key_here'")
    sys.exit(1)

# ============================================================================
# KONFIGURASI UTAMA
# ============================================================================

# Alamat Solana bervolume tinggi di Mainnet yang akan dianalisis
TARGET_ADDRESS = "9yj3zvLS3fDMqi1F8zhkaWfq8TZpZWHe6cz1Sgt7djXf"  

# Parameter batas maksimal transaksi yang akan diambil
MAX_TRANSACTIONS_TO_FETCH = 100000

# URL endpoint Helius API
HELIUS_BASE_URL = "https://api.helius.xyz/v0"

# Konfigurasi rate limiting
API_DELAY_SECONDS = 0.1  # Jeda antar panggilan API
BATCH_SIZE = 100  # Jumlah transaksi per batch

# File output untuk logging
CSV_OUTPUT_FILE = "nonce_forensic_log_100k_phantom.csv"

# ============================================================================
# FUNGSI UTILITAS
# ============================================================================

def log_info(message: str) -> None:
    """Print pesan informasi dengan timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def extract_r_component(signature_b58: str) -> Optional[str]:
    """
    Ekstrak komponen R (32 byte pertama) dari signature Ed25519.
    
    Args:
        signature_b58: Signature dalam format base58
        
    Returns:
        String hex dari komponen R atau None jika error
    """
    try:
        # Decode base58 signature menjadi bytes
        signature_bytes = base58.b58decode(signature_b58)
        
        # Signature Ed25519 adalah 64 bytes, komponen R adalah 32 bytes pertama
        if len(signature_bytes) != 64:
            return None
            
        r_component = signature_bytes[:32]
        return r_component.hex()
        
    except Exception as e:
        log_info(f"❌ Error ekstraksi komponen R: {e}")
        return None

def extract_message_hash(transaction: Dict) -> Optional[str]:
    """
    Ekstrak message hash dari data transaksi untuk analisis nonce reuse.
    
    Args:
        transaction: Data transaksi dari API
        
    Returns:
        String hex dari message hash atau None jika error
    """
    try:
        # Metode 1: Cek jika ada message hash langsung di response
        if 'message' in transaction:
            message_data = transaction['message']
            if isinstance(message_data, str):
                # Jika message sudah dalam format string, hash langsung
                return hashlib.sha256(message_data.encode()).hexdigest()
            elif isinstance(message_data, dict):
                # Jika message dalam format dict, serialize dulu
                message_str = json.dumps(message_data, sort_keys=True)
                return hashlib.sha256(message_str.encode()).hexdigest()
        
        # Metode 2: Ekstrak dari transaction.message
        if 'transaction' in transaction and 'message' in transaction['transaction']:
            message = transaction['transaction']['message']
            message_str = json.dumps(message, sort_keys=True)
            return hashlib.sha256(message_str.encode()).hexdigest()
        
        # Metode 3: Buat hash dari signature sebagai fallback
        signature = get_transaction_signature(transaction)
        if signature:
            return hashlib.sha256(signature.encode()).hexdigest()
        
        # Metode 4: Hash dari seluruh transaction data sebagai last resort
        transaction_str = json.dumps(transaction, sort_keys=True)
        return hashlib.sha256(transaction_str.encode()).hexdigest()
        
    except Exception as e:
        log_info(f"❌ Error ekstraksi message hash: {e}")
        # Fallback: gunakan timestamp sebagai unique identifier
        try:
            block_time = transaction.get('blockTime', int(time.time()))
            fallback_str = f"fallback_{block_time}_{hash(str(transaction))}"
            return hashlib.sha256(fallback_str.encode()).hexdigest()
        except:
            return None

def initialize_csv_log() -> None:
    """Inisialisasi file CSV untuk logging."""
    with open(CSV_OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['signature_hash', 'block_time_utc', 'r_component_hex', 'message_hash_hex'])
    log_info(f"📄 File CSV '{CSV_OUTPUT_FILE}' telah diinisialisasi dengan kolom message_hash_hex")

def write_to_csv(signature_hash: str, block_time: int, r_component_hex: str, message_hash_hex: str) -> None:
    """Tulis data ke file CSV."""
    try:
        # Konversi Unix timestamp ke UTC datetime
        block_time_utc = datetime.fromtimestamp(block_time).strftime("%Y-%m-%d %H:%M:%S")
        
        with open(CSV_OUTPUT_FILE, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([signature_hash, block_time_utc, r_component_hex, message_hash_hex])
    except Exception as e:
        log_info(f"❌ Error penulisan CSV: {e}")

def fetch_transaction_history(address: str, before: Optional[str] = None) -> Dict:
    """
    Ambil riwayat transaksi dari Helius API.
    
    Args:
        address: Alamat Solana yang akan dianalisis
        before: Signature untuk paginasi (opsional)
        
    Returns:
        Response data dari API
    """
    # Format URL dengan API key langsung di URL
    url = f"{HELIUS_BASE_URL}/addresses/{address}/transactions?api-key={HELIUS_API_KEY}"
    
    params = {
        'limit': BATCH_SIZE
    }
    
    if before:
        params['before'] = before
    
    try:
        log_info(f"🔗 API URL: {url}")
        log_info(f"📋 Parameters: {params}")
        
        response = requests.get(url, params=params, timeout=30)
        
        log_info(f"📊 Status Code: {response.status_code}")
        log_info(f"📄 Response length: {len(response.text)} chars")
        
        response.raise_for_status()
        json_response = response.json()
        
        log_info(f"📦 Response type: {type(json_response)}")
        if isinstance(json_response, list):
            log_info(f"📋 Number of transactions: {len(json_response)}")
        elif isinstance(json_response, dict):
            log_info(f"📋 Response keys: {list(json_response.keys())}")
        
        return json_response
        
    except requests.exceptions.RequestException as e:
        log_info(f"❌ Error API call: {e}")
        if hasattr(e, 'response') and e.response:
            log_info(f"❌ Response text: {e.response.text}")
        return {}

def is_target_signer(transaction: Dict, target_address: str) -> bool:
    """
    Periksa apakah alamat target adalah signer dari transaksi.
    
    Args:
        transaction: Data transaksi dari API
        target_address: Alamat target yang dicari
        
    Returns:
        True jika alamat target adalah signer
    """
    try:
        # Debug: print transaction structure
        log_info(f"🔍 Checking transaction structure: {list(transaction.keys())}")
        
        # Cek di feePayer (biasanya signer utama)
        if 'feePayer' in transaction and transaction['feePayer'] == target_address:
            log_info(f"✅ Found target as feePayer: {target_address}")
            return True
        
        # Cek di accountData untuk native balance changes (indikasi signer)
        if 'accountData' in transaction:
            for account_data in transaction['accountData']:
                if (account_data.get('account') == target_address and 
                    account_data.get('nativeBalanceChange', 0) != 0):
                    log_info(f"✅ Found target with balance change: {target_address}")
                    return True
        
        # Cek di transaction.message.accountKeys (format RPC)
        if 'transaction' in transaction and 'message' in transaction['transaction']:
            message = transaction['transaction']['message']
            if 'accountKeys' in message and len(message['accountKeys']) > 0:
                if message['accountKeys'][0] == target_address:
                    log_info(f"✅ Found target as first accountKey: {target_address}")
                    return True
        
        # Cek di level root untuk backward compatibility
        if 'accountKeys' in transaction and len(transaction['accountKeys']) > 0:
            if transaction['accountKeys'][0] == target_address:
                log_info(f"✅ Found target in root accountKeys: {target_address}")
                return True
        
        # Cek di instructions untuk program interactions
        if 'instructions' in transaction:
            for instruction in transaction['instructions']:
                if 'accounts' in instruction and target_address in instruction['accounts']:
                    log_info(f"✅ Found target in instruction accounts: {target_address}")
                    return True
        
        return False
        
    except Exception as e:
        log_info(f"❌ Error pemeriksaan signer: {e}")
        return False

def get_transaction_signature(transaction: Dict) -> Optional[str]:
    """
    Ekstrak signature dari data transaksi.
    
    Args:
        transaction: Data transaksi dari API
        
    Returns:
        Signature string atau None jika tidak ditemukan
    """
    try:
        # Cek di berbagai lokasi yang mungkin
        if 'signature' in transaction:
            return transaction['signature']
            
        if 'transaction' in transaction and 'signatures' in transaction['transaction']:
            signatures = transaction['transaction']['signatures']
            if len(signatures) > 0:
                return signatures[0]
        
        if 'signatures' in transaction and len(transaction['signatures']) > 0:
            return transaction['signatures'][0]
            
        return None
        
    except Exception as e:
        log_info(f"❌ Error ekstraksi signature: {e}")
        return None

def test_api_connection() -> bool:
    """Test koneksi API dan validasi API key."""
    log_info("🔬 Testing API connection...")
    
    # Test dengan endpoint yang sederhana dulu
    test_url = f"https://api.helius.xyz/v0/addresses/{TARGET_ADDRESS}/balances?api-key={HELIUS_API_KEY}"
    
    try:
        response = requests.get(test_url, timeout=10)
        log_info(f"🔗 Test URL: {test_url}")
        log_info(f"📊 Status Code: {response.status_code}")
        log_info(f"📄 Response: {response.text[:200]}...")
        
        if response.status_code == 200:
            log_info("✅ API connection successful")
            return True
        elif response.status_code == 401:
            log_info("❌ API Key invalid atau tidak diotorisasi")
            return False
        else:
            log_info(f"⚠️  API returned status {response.status_code}")
            return False
            
    except Exception as e:
        log_info(f"❌ API connection test failed: {e}")
        return False
def analyze_nonce_reuse() -> None:
    """Fungsi utama untuk analisis nonce reuse."""
    
    log_info("🔍 Memulai Analisis Forensik Nonce Reuse - Solana Mainnet")
    log_info(f"📍 Target Address: {TARGET_ADDRESS}")
    log_info(f"📊 Maksimal transaksi: {MAX_TRANSACTIONS_TO_FETCH}")
    log_info(f"🔑 API Key: {HELIUS_API_KEY[:12]}...{HELIUS_API_KEY[-4:]}")
    
    # Validasi alamat target
    if TARGET_ADDRESS == "AlamatTargetDiMainnet":
        log_info("❌ ERROR: Silakan ganti TARGET_ADDRESS dengan alamat Solana yang valid")
        return
    
    # Test API connection
    if not test_api_connection():
        log_info("❌ ERROR: Gagal terhubung ke API. Periksa API key dan koneksi internet.")
        return
    
    # Inisialisasi
    initialize_csv_log()
    r_component_set: Set[str] = set()
    message_hash_set: Set[str] = set()
    r_message_pairs: Set[tuple] = set()  # Track kombinasi (R, message_hash)
    total_processed = 0
    before_signature = None
    duplicate_count = 0
    message_duplicate_count = 0
    
    log_info("🚀 Memulai pengambilan data transaksi...")
    
    # Loop paginasi utama
    while total_processed < MAX_TRANSACTIONS_TO_FETCH:
        # Ambil batch transaksi
        log_info(f"📥 Mengambil batch transaksi... (Before: {before_signature[:8] + '...' if before_signature else 'None'})")
        
        transaction_data = fetch_transaction_history(TARGET_ADDRESS, before_signature)
        
        if not transaction_data:
            log_info("❌ Tidak ada data dari API")
            break
            
        # Handle different response formats
        transactions = []
        if isinstance(transaction_data, list):
            transactions = transaction_data
        elif isinstance(transaction_data, dict):
            # If API returns paginated format
            if 'transactions' in transaction_data:
                transactions = transaction_data['transactions']
            else:
                log_info(f"❌ Format response tidak dikenal: {list(transaction_data.keys())}")
                break
        
        if len(transactions) == 0:
            log_info("✅ Tidak ada transaksi lebih lanjut yang ditemukan")
            break
        
        batch_processed = 0
        
        # Proses setiap transaksi dalam batch
        for transaction in transactions:
            if total_processed >= MAX_TRANSACTIONS_TO_FETCH:
                break
                
            # Filter: pastikan alamat target adalah signer
            log_info(f"🔍 Memproses transaksi: {get_transaction_signature(transaction) or 'Unknown'}")
            
            if not is_target_signer(transaction, TARGET_ADDRESS):
                log_info(f"⏭️  Transaksi dilewati - bukan dari alamat target")
                continue
            
            # Ekstrak signature
            signature = get_transaction_signature(transaction)
            if not signature:
                continue
            
            # Ekstrak komponen R
            r_component_hex = extract_r_component(signature)
            if not r_component_hex:
                continue
            
            # Ekstrak message hash
            message_hash_hex = extract_message_hash(transaction)
            if not message_hash_hex:
                continue
            
            # Periksa duplikasi nonce (komponen R)
            if r_component_hex in r_component_set:
                duplicate_count += 1
                log_info(f"⚠️  DUPLIKASI NONCE (R) DITEMUKAN: {r_component_hex}")
            else:
                r_component_set.add(r_component_hex)
            
            # Periksa duplikasi message hash
            if message_hash_hex in message_hash_set:
                message_duplicate_count += 1
                log_info(f"⚠️  DUPLIKASI MESSAGE HASH DITEMUKAN: {message_hash_hex[:16]}...")
            else:
                message_hash_set.add(message_hash_hex)
            
            # Track kombinasi (R, message_hash) untuk analisis nonce reuse
            r_message_pair = (r_component_hex, message_hash_hex)
            r_message_pairs.add(r_message_pair)
            
            # Ambil block time
            block_time = transaction.get('blockTime', 0)
            
            # Tulis ke CSV
            write_to_csv(signature, block_time, r_component_hex, message_hash_hex)
            
            total_processed += 1
            batch_processed += 1
            
            # Update signature untuk paginasi
            before_signature = signature
        
        # Log progress
        unique_nonces = len(r_component_set)
        unique_messages = len(message_hash_set)
        unique_pairs = len(r_message_pairs)
        log_info(f"📊 Batch selesai: {batch_processed} transaksi | "
                f"Total diproses: {total_processed} | "
                f"Nonce unik (R): {unique_nonces} | "
                f"Message unik: {unique_messages} | "
                f"Pasangan unik (R,M): {unique_pairs} | "
                f"Duplikasi R: {duplicate_count} | "
                f"Duplikasi Message: {message_duplicate_count}")
        
        # Jeda untuk menghormati rate limit
        time.sleep(API_DELAY_SECONDS)
        
        # Break jika tidak ada transaksi baru
        if batch_processed == 0:
            log_info("✅ Tidak ada transaksi baru dalam batch")
            break
    
    # Analisis akhir dan kesimpulan
    log_info("=" * 70)
    log_info("📈 ANALISIS FORENSIK SELESAI")
    log_info("=" * 70)
    
    unique_nonces = len(r_component_set)
    unique_messages = len(message_hash_set)
    unique_pairs = len(r_message_pairs)
    
    # Analisis nonce reuse berdasarkan kombinasi R dan message hash
    potential_nonce_reuse = total_processed - unique_pairs
    
    log_info(f"📊 **STATISTIK LENGKAP ANALISIS FORENSIK**")
    log_info(f"🔢 Total transaksi diproses: {total_processed}")
    log_info(f"🔑 Nonce unik (komponen R): {unique_nonces}")
    log_info(f"📝 Message hash unik: {unique_messages}")
    log_info(f"🔗 Pasangan unik (R, Message): {unique_pairs}")
    log_info(f"⚠️  Duplikasi komponen R: {duplicate_count}")
    log_info(f"⚠️  Duplikasi message hash: {message_duplicate_count}")
    log_info(f"🚨 Potensi nonce reuse: {potential_nonce_reuse}")
    
    if duplicate_count == 0 and potential_nonce_reuse == 0:
        log_info(f"✅ **Analisis Forensik Selesai**: Dari {total_processed} transaksi yang dianalisis, "
                f"tidak ditemukan adanya bukti nonce reuse.")
        log_info(f"🔒 Implementasi Ed25519 tampak aman dan sesuai standar.")
    else:
        log_info(f"❌ **TEMUAN KRITIS KEAMANAN**:")
        if duplicate_count > 0:
            log_info(f"   🔴 Ditemukan {duplicate_count} duplikasi komponen R")
            log_info(f"   📊 Rasio duplikasi R: {(duplicate_count / total_processed * 100):.2f}%")
        
        if message_duplicate_count > 0:
            log_info(f"   🟡 Ditemukan {message_duplicate_count} duplikasi message hash")
            log_info(f"   📊 Rasio duplikasi message: {(message_duplicate_count / total_processed * 100):.2f}%")
        
        if potential_nonce_reuse > 0:
            log_info(f"   🚨 Potensi nonce reuse: {potential_nonce_reuse} kasus")
            log_info(f"   📊 Rasio nonce reuse: {(potential_nonce_reuse / total_processed * 100):.2f}%")
        
        log_info(f"⚠️  **KESIMPULAN**: Implementasi Ed25519 menunjukkan kerentanan keamanan!")
        log_info(f"🔍 Diperlukan investigasi lebih lanjut terhadap wallet/signer yang digunakan.")
    
    # Analisis efektivitas pengukuran
    r_uniqueness_ratio = (unique_nonces / total_processed * 100) if total_processed > 0 else 0
    message_uniqueness_ratio = (unique_messages / total_processed * 100) if total_processed > 0 else 0
    
    log_info(f"📈 **METRIK KEUNIKAN**:")
    log_info(f"   🔑 Rasio keunikan komponen R: {r_uniqueness_ratio:.2f}%")
    log_info(f"   📝 Rasio keunikan message hash: {message_uniqueness_ratio:.2f}%")
    log_info(f"   🎯 Efektivitas deteksi nonce reuse: {((unique_pairs / total_processed) * 100):.2f}%")
    
    log_info(f"📄 Data lengkap dengan message_hash_hex tersimpan di: {CSV_OUTPUT_FILE}")
    log_info("🏁 Analisis forensik selesai - Data siap untuk validasi dengan nonce_validator.py")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    try:
        analyze_nonce_reuse()
    except KeyboardInterrupt:
        log_info("⏹️  Analisis dihentikan oleh pengguna")
    except Exception as e:
        log_info(f"❌ Error fatal: {e}")
        sys.exit(1)