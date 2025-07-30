# enhanced_replay_tester.py (Fixed Version - Scientific Approach)

import csv
import time
import logging
from datetime import datetime
import base58

try:
    import config
except ImportError:
    print("FATAL: File config.py tidak ditemukan. Harap buat file tersebut dengan variabel WALLET_PRIVATE_KEY.")
    exit()

# Solana imports
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.message import Message
from solders.transaction import VersionedTransaction
from solana.rpc.commitment import Confirmed
from solana.rpc.core import RPCException
from solana.rpc.types import TxOpts
from solders.signature import Signature

# === Konfigurasi Logging Diperkaya ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('enhanced_replay_attack.log', 'w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Konstanta ===
TRANSFER_AMOUNT_LAMPORTS = 10000
AIRDROP_AMOUNT_SOL = 0.5
CSV_FILENAME = "enhanced_replay_attack_log4.csv"
CSV_HEADERS = [
    "iteration_id", "timestamp_utc", "scenario_name", "status",
    "signature", "blockhash_used", "error_message", 
    "initial_balance", "intermediate_balance", "final_balance",
    "balance_change", "signature_match", "slot_info"
]
RECEIVER_WALLETS = [
    "B6DY9vuaTwSJhA193QW2TTSzN7Xq7LxDNP7sKWfydBFp",
    "CWWgrRSFprMskzux5rWJviAdd74uqfETdniq9B8xewGh",
    "8Y8dMr9zMgCBbBt9MPwZphKpFaffFy3sJAHv2PDhu3K8",
    "44SQNhw9mQ5ArLLCQqZAkGiAWY1vHEhMouGK4FFfWaJY",
    "EV6NcXS1ZpUZPLRCkQ3ifAxGLB6nScBK4jY1u48K2fzH"
]

class TransactionWithMeta:
    """Wrapper class to store transaction with additional metadata"""
    def __init__(self, transaction: VersionedTransaction, last_valid_height: int):
        self.transaction = transaction
        self.last_valid_height = last_valid_height
        self.message = transaction.message
        self.signatures = transaction.signatures

def setup_clients():
    """Inisialisasi koneksi ke Solana Devnet dan Testnet."""
    try:
        DEVNET_RPC_URL = "https://solana-devnet.g.alchemy.com/v2/H4UsVfnsrnMYIXz5ECoM2"
        devnet_client = Client(DEVNET_RPC_URL)
        testnet_client = Client("https://api.testnet.solana.com")
        
        devnet_client.get_slot()
        logger.info(f"✅ Koneksi ke Devnet RPC berhasil.")
        return devnet_client, testnet_client
    except Exception as e:
        logger.error(f"❌ GAGAL menghubungkan ke Solana RPC: {e}")
        return None, None

def load_keypair_from_config():
    """Memuat keypair pengirim dari variabel di config.py."""
    try: 
        if not hasattr(config, 'WALLET_PRIVATE_KEY') or not config.WALLET_PRIVATE_KEY:
            raise ValueError("Variabel WALLET_PRIVATE_KEY kosong atau tidak ada di config.py")
        private_key_bytes = base58.b58decode(config.WALLET_PRIVATE_KEY)
        sender_keypair = Keypair.from_bytes(private_key_bytes)
        logger.info(f"✅ Keypair berhasil dimuat untuk wallet: {sender_keypair.pubkey()}")
        return sender_keypair
    except Exception as e:
        logger.error(f"❌ GAGAL memuat keypair dari config.py: {e}")
        return None

def get_balance(client, pubkey):
    """Mendapatkan saldo wallet dalam SOL."""
    try:
        balance_lamports = client.get_balance(pubkey).value
        return balance_lamports / 1e9
    except Exception as e:
        logger.error(f"❌ Gagal mendapatkan saldo untuk {pubkey}: {e}")
        return None

def log_to_csv(writer, iteration_id, scenario_name, result):
    """Menulis satu baris hasil ke file CSV dengan data yang diperkaya."""
    timestamp_utc = datetime.utcnow().isoformat() + "Z"
    row = {
        "iteration_id": iteration_id,
        "timestamp_utc": timestamp_utc,
        "scenario_name": scenario_name,
        "status": result.get("status", "ERROR"),
        "signature": result.get("signature", ""),
        "blockhash_used": result.get("blockhash", ""),
        "error_message": result.get("error_message", ""),
        "initial_balance": result.get("initial_balance", ""),
        "intermediate_balance": result.get("intermediate_balance", ""),
        "final_balance": result.get("final_balance", ""),
        "balance_change": result.get("balance_change", ""),
        "signature_match": result.get("signature_match", ""),
        "slot_info": result.get("slot_info", "")
    }
    writer.writerow(row)
    logger.info(f"📄 CSV LOG | Iteration {iteration_id} | {scenario_name}: {row['status']}")

def create_and_sign_transaction(client, sender_keypair, recipient_address_str: str):
    """Membuat dan menandatangani transaksi transfer SOL ke penerima yang ditentukan."""
    try:
        try:
            recipient_pubkey = Pubkey.from_string(recipient_address_str)
        except Exception as e:
            logger.error(f"❌ Invalid recipient address {recipient_address_str}: {e}")
            return None
        
        # Dapatkan recent blockhash dengan informasi lastValidBlockHeight
        blockhash_resp = client.get_latest_blockhash(commitment="confirmed")
        if not blockhash_resp.value:
            logger.error("❌ GAGAL mendapatkan recent blockhash.")
            return None
        
        blockhash = blockhash_resp.value.blockhash
        last_valid_height = blockhash_resp.value.last_valid_block_height
        
        logger.info(f"🔗 Menggunakan blockhash: {blockhash}")
        logger.info(f"🔗 Valid hingga block height: {last_valid_height}")
        
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=recipient_pubkey,
                lamports=TRANSFER_AMOUNT_LAMPORTS
            )
        )
        
        message = Message.new_with_blockhash([transfer_instruction], sender_keypair.pubkey(), blockhash)
        transaction = VersionedTransaction(message, [sender_keypair])
        
        # Wrap transaction dengan metadata
        transaction_with_meta = TransactionWithMeta(transaction, last_valid_height)
        
        logger.info(f"✅ Transaksi baru berhasil dibuat untuk penerima {recipient_address_str}")
        return transaction_with_meta
    except Exception as e:
        logger.error(f"❌ GAGAL membuat transaksi: {e}")
        return None

def send_transaction_with_balance_tracking(client, transaction_with_meta, sender_keypair, scenario_name):
    """Mengirim transaksi dengan pelacakan saldo yang presisi."""
    signature_str = ""
    transaction = transaction_with_meta.transaction
    
    # FASE SETUP: Catat saldo awal
    logger.info(f"[{scenario_name}] === FASE SETUP ===")
    initial_balance = get_balance(client, sender_keypair.pubkey())
    logger.info(f"[{scenario_name}] Initial balance: {initial_balance:.6f} SOL")
    
    try:
        if initial_balance is None:
            raise Exception("Gagal mendapatkan saldo awal")
        
        balance_lamports = int(initial_balance * 1e9)
        if balance_lamports < TRANSFER_AMOUNT_LAMPORTS:
            error_msg = f"Balance tidak mencukupi: {balance_lamports} < {TRANSFER_AMOUNT_LAMPORTS} lamports"
            logger.error(f"❌ [{scenario_name}] {error_msg}")
            return {
                "status": "INSUFFICIENT_BALANCE",
                "signature": "",
                "blockhash": str(transaction.message.recent_blockhash),
                "error_message": error_msg,
                "initial_balance": initial_balance,
                "intermediate_balance": initial_balance,
                "final_balance": initial_balance,
                "balance_change": 0,
                "signature_match": "N/A",
                "slot_info": ""
            }
        
        # FASE EXECUTION: Kirim transaksi
        logger.info(f"[{scenario_name}] === FASE EXECUTION ===")
        tx_opts = TxOpts(
            skip_preflight=False,
            preflight_commitment="confirmed",
            max_retries=3
        )
        
        logger.info(f"[{scenario_name}] Mengirim transaksi...")
        send_result = client.send_transaction(transaction, opts=tx_opts)
        
        if hasattr(send_result, 'value') and send_result.value:
            signature_obj = send_result.value
            signature_str = str(signature_obj)
            logger.info(f"[{scenario_name}] Transaksi dikirim dengan signature: {signature_str}")
            
            # Tunggu konfirmasi
            logger.info(f"[{scenario_name}] Menunggu konfirmasi...")
            confirm_result = client.confirm_transaction(signature_obj, commitment="confirmed")
            
            if confirm_result.value:
                # FASE VERIFICATION: Periksa saldo setelah transaksi
                logger.info(f"[{scenario_name}] === FASE VERIFICATION ===")
                time.sleep(2)  # Beri waktu untuk update saldo
                final_balance = get_balance(client, sender_keypair.pubkey())
                balance_change = final_balance - initial_balance if final_balance else 0
                
                logger.info(f"[{scenario_name}] Transaksi {signature_str} berhasil dikonfirmasi.")
                logger.info(f"[{scenario_name}] Final balance: {final_balance:.6f} SOL")
                logger.info(f"[{scenario_name}] Balance change: {balance_change:.6f} SOL")
                logger.info(f"[{scenario_name}] Explorer: https://explorer.solana.com/tx/{signature_str}?cluster=devnet")
                
                return {
                    "status": "SUCCESS",
                    "signature": signature_str,
                    "blockhash": str(transaction.message.recent_blockhash),
                    "error_message": "",
                    "initial_balance": initial_balance,
                    "intermediate_balance": final_balance,
                    "final_balance": final_balance,
                    "balance_change": balance_change,
                    "signature_match": "N/A",
                    "slot_info": ""
                }
            else:
                logger.error(f"❌ [{scenario_name}] Transaksi {signature_str} gagal dikonfirmasi.")
                final_balance = get_balance(client, sender_keypair.pubkey())
                return {
                    "status": "UNCONFIRMED",
                    "signature": signature_str,
                    "blockhash": str(transaction.message.recent_blockhash),
                    "error_message": "Transaction sent but not confirmed",
                    "initial_balance": initial_balance,
                    "intermediate_balance": final_balance,
                    "final_balance": final_balance,
                    "balance_change": (final_balance - initial_balance) if final_balance else 0,
                    "signature_match": "N/A",
                    "slot_info": ""
                }
        else:
            logger.error(f"❌ [{scenario_name}] Gagal mengirim transaksi")
            final_balance = get_balance(client, sender_keypair.pubkey())
            return {
                "status": "SEND_FAILED",
                "signature": "",
                "blockhash": str(transaction.message.recent_blockhash),
                "error_message": "Send transaction returned no signature",
                "initial_balance": initial_balance,
                "intermediate_balance": final_balance,
                "final_balance": final_balance,
                "balance_change": (final_balance - initial_balance) if final_balance else 0,
                "signature_match": "N/A",
                "slot_info": ""
            }
        
    except RPCException as rpc_err:
        logger.error(f"❌ [{scenario_name}] RPC Error: {rpc_err}")
        final_balance = get_balance(client, sender_keypair.pubkey())
        return {
            "status": "RPC_ERROR",
            "signature": signature_str,
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": str(rpc_err),
            "initial_balance": initial_balance,
            "intermediate_balance": final_balance,
            "final_balance": final_balance,
            "balance_change": (final_balance - initial_balance) if final_balance else 0,
            "signature_match": "N/A",
            "slot_info": ""
        }
    except Exception as e:
        logger.error(f"❌ [{scenario_name}] Unexpected error: {e}")
        final_balance = get_balance(client, sender_keypair.pubkey())
        return {
            "status": "ERROR",
            "signature": signature_str,
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": str(e),
            "initial_balance": initial_balance,
            "intermediate_balance": final_balance,
            "final_balance": final_balance,
            "balance_change": (final_balance - initial_balance) if final_balance else 0,
            "signature_match": "N/A",
            "slot_info": ""
        }

def test_direct_replay(client, transaction_with_meta, sender_keypair, original_signature):
    """Test direct replay dengan pelacakan signature matching."""
    logger.info("\n🧪 === TEST: DIRECT REPLAY (Blockhash Valid) ===")
    
    transaction = transaction_with_meta.transaction
    
    # FASE SETUP
    logger.info("[Direct Replay] === FASE SETUP ===")
    initial_balance = get_balance(client, sender_keypair.pubkey())
    logger.info(f"[Direct Replay] Initial balance: {initial_balance:.6f} SOL")
    
    # FASE EXECUTION
    logger.info("[Direct Replay] === FASE EXECUTION ===")
    logger.info("[Direct Replay] Mengirim ulang transaksi yang identik...")
    
    try:
        send_result = client.send_transaction(transaction)
        if hasattr(send_result, 'value') and send_result.value:
            replay_signature = str(send_result.value)
            logger.info(f"[Direct Replay] Replay returned signature: {replay_signature}")
            
            # Tunggu sebentar untuk konfirmasi
            time.sleep(3)
            
            # FASE VERIFICATION
            logger.info("[Direct Replay] === FASE VERIFICATION ===")
            final_balance = get_balance(client, sender_keypair.pubkey())
            signature_match = "IDENTICAL" if replay_signature == original_signature else "DIFFERENT"
            balance_change = final_balance - initial_balance if final_balance else 0
            
            logger.info("[Direct Replay] RESULT:")
            logger.info(f"[Direct Replay] > Original signature: {original_signature}")
            logger.info(f"[Direct Replay] > Replay signature:   {replay_signature}")
            logger.info(f"[Direct Replay] > Signature match:    {signature_match}")
            logger.info(f"[Direct Replay] > Balance change:     {balance_change:.6f} SOL")
            
            if signature_match == "IDENTICAL" and abs(balance_change) < 0.000001:
                logger.info("✅ [Direct Replay] TEST PASSED: No double-spend occurred.")
                status = "REPLAY_RECOGNIZED"
            else:
                logger.warning("⚠️ [Direct Replay] TEST INCONCLUSIVE: Unexpected behavior.")
                status = "REPLAY_UNEXPECTED"
            
            return {
                "status": status,
                "signature": replay_signature,
                "blockhash": str(transaction.message.recent_blockhash),
                "error_message": "",
                "initial_balance": initial_balance,
                "intermediate_balance": final_balance,
                "final_balance": final_balance,
                "balance_change": balance_change,
                "signature_match": signature_match,
                "slot_info": ""
            }
        else:
            raise Exception("Tidak ada signature yang dikembalikan")
            
    except Exception as e:
        logger.info(f"[Direct Replay] Replay ditolak dengan error: {e}")
        final_balance = get_balance(client, sender_keypair.pubkey())
        return {
            "status": "REPLAY_REJECTED",
            "signature": "",
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": str(e),
            "initial_balance": initial_balance,
            "intermediate_balance": final_balance,
            "final_balance": final_balance,
            "balance_change": (final_balance - initial_balance) if final_balance else 0,
            "signature_match": "N/A",
            "slot_info": ""
        }

def test_expired_replay(client, transaction_with_meta, sender_keypair):
    """Test expired replay dengan monitoring slot deterministik."""
    logger.info("\n🧪 === TEST: EXPIRED REPLAY (Blockhash Kedaluwarsa) ===")
    
    transaction = transaction_with_meta.transaction
    last_valid_height = transaction_with_meta.last_valid_height
    
    # FASE SETUP
    logger.info("[Expired Replay] === FASE SETUP ===")
    initial_balance = get_balance(client, sender_keypair.pubkey())
    logger.info(f"[Expired Replay] Initial balance: {initial_balance:.6f} SOL")
    logger.info(f"[Expired Replay] Blockhash valid hingga block height: {last_valid_height}")
    
    # FASE EXECUTION
    logger.info("[Expired Replay] === FASE EXECUTION ===")
    logger.info(f"[Expired Replay] Menunggu jaringan melampaui block height {last_valid_height}...")
    
    current_slot = 0
    while True:
        try:
            current_slot = client.get_slot().value
            logger.info(f"[Expired Replay] Current slot: {current_slot}... {'EXPIRED!' if current_slot > last_valid_height else 'Still valid.'}")
            
            if current_slot > last_valid_height:
                logger.info("[Expired Replay] Blockhash telah kedaluwarsa! Mengirim transaksi...")
                break
                
            time.sleep(10)
        except Exception as e:
            logger.error(f"[Expired Replay] Error checking slot: {e}")
            time.sleep(10)
    
    # Kirim transaksi yang sudah kedaluwarsa
    try:
        send_result = client.send_transaction(transaction)
        logger.warning("[Expired Replay] Transaksi kedaluwarsa berhasil dikirim (tidak diharapkan)")
        
        final_balance = get_balance(client, sender_keypair.pubkey())
        return {
            "status": "EXPIRED_ACCEPTED",
            "signature": str(send_result.value) if send_result.value else "",
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": "Expired transaction was unexpectedly accepted",
            "initial_balance": initial_balance,
            "intermediate_balance": final_balance,
            "final_balance": final_balance,
            "balance_change": (final_balance - initial_balance) if final_balance else 0,
            "signature_match": "N/A",
            "slot_info": f"current_slot:{current_slot}, last_valid:{last_valid_height}"
        }
        
    except Exception as e:
        # FASE VERIFICATION
        logger.info("[Expired Replay] === FASE VERIFICATION ===")
        logger.info(f"[Expired Replay] Transaksi ditolak dengan error: {e}")
        
        if "blockhash not found" in str(e).lower() or "block height exceeded" in str(e).lower():
            logger.info("✅ [Expired Replay] TEST PASSED: Transaksi kedaluwarsa berhasil ditolak.")
            status = "EXPIRED_REJECTED_CORRECTLY"
        else:
            logger.warning("⚠️ [Expired Replay] Transaksi ditolak, tapi bukan karena blockhash kedaluwarsa.")
            status = "EXPIRED_REJECTED_OTHER"
        
        final_balance = get_balance(client, sender_keypair.pubkey())
        return {
            "status": status,
            "signature": "",
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": str(e),
            "initial_balance": initial_balance,
            "intermediate_balance": final_balance,
            "final_balance": final_balance,
            "balance_change": (final_balance - initial_balance) if final_balance else 0,
            "signature_match": "N/A",
            "slot_info": f"current_slot:{current_slot}, last_valid:{last_valid_height}"
        }

def test_cross_network_replay(source_client, target_client, transaction_with_meta, sender_keypair, source_name, target_name):
    """Test cross-network replay dengan analisis mendalam."""
    logger.info(f"\n🧪 === TEST: CROSS-NETWORK REPLAY ({source_name} -> {target_name}) ===")
    
    transaction = transaction_with_meta.transaction
    
    # FASE SETUP
    logger.info(f"[Cross-Network] === FASE SETUP ===")
    try:
        initial_balance_source = get_balance(source_client, sender_keypair.pubkey())
        initial_balance_target = get_balance(target_client, sender_keypair.pubkey())
        logger.info(f"[Cross-Network] Balance di {source_name}: {initial_balance_source:.6f} SOL")
        logger.info(f"[Cross-Network] Balance di {target_name}: {initial_balance_target:.6f} SOL")
    except:
        logger.warning("[Cross-Network] Gagal mendapatkan saldo di salah satu jaringan")
        initial_balance_source = 0
        initial_balance_target = 0
    
    # FASE EXECUTION
    logger.info(f"[Cross-Network] === FASE EXECUTION ===")
    logger.info(f"[Cross-Network] Mencoba mengirim transaksi dari {source_name} ke {target_name}...")
    
    try:
        send_result = target_client.send_transaction(transaction)
        logger.warning(f"[Cross-Network] Transaksi lintas jaringan berhasil dikirim (tidak diharapkan)")
        
        return {
            "status": "CROSS_NETWORK_ACCEPTED",
            "signature": str(send_result.value) if send_result.value else "",
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": f"Cross-network transaction {source_name}->{target_name} was unexpectedly accepted",
            "initial_balance": initial_balance_target,
            "intermediate_balance": initial_balance_target,
            "final_balance": initial_balance_target,
            "balance_change": 0,
            "signature_match": "N/A",
            "slot_info": f"source:{source_name}, target:{target_name}"
        }
        
    except Exception as e:
        # FASE VERIFICATION
        logger.info(f"[Cross-Network] === FASE VERIFICATION ===")
        logger.info(f"[Cross-Network] Transaksi lintas jaringan ditolak: {e}")
        
        error_msg = str(e).lower()
        if "blockhash not found" in error_msg or "invalid blockhash" in error_msg:
            logger.info("✅ [Cross-Network] TEST PASSED: Transaksi lintas jaringan ditolak karena blockhash mismatch.")
            status = "CROSS_NETWORK_REJECTED_BLOCKHASH"
        elif "genesis" in error_msg:
            logger.info("✅ [Cross-Network] TEST PASSED: Transaksi lintas jaringan ditolak karena genesis hash mismatch.")
            status = "CROSS_NETWORK_REJECTED_GENESIS"
        else:
            logger.info("✅ [Cross-Network] TEST PASSED: Transaksi lintas jaringan ditolak (alasan lain).")
            status = "CROSS_NETWORK_REJECTED_OTHER"
        
        return {
            "status": status,
            "signature": "",
            "blockhash": str(transaction.message.recent_blockhash),
            "error_message": str(e),
            "initial_balance": initial_balance_target,
            "intermediate_balance": initial_balance_target,
            "final_balance": initial_balance_target,
            "balance_change": 0,
            "signature_match": "N/A",
            "slot_info": f"source:{source_name}, target:{target_name}"
        }

def run_enhanced_experiment_cycle(iteration_id, devnet_client, testnet_client, sender_keypair, csv_writer, recipient_address: str):
    """Menjalankan siklus eksperimen dengan metodologi ilmiah yang diperkaya."""
    logger.info(f"\n🔬 === EKSPERIMEN ILMIAH #{iteration_id} | Penerima: {recipient_address} ===")
    
    # Buat transaksi baru
    original_transaction_with_meta = create_and_sign_transaction(devnet_client, sender_keypair, recipient_address)
    if not original_transaction_with_meta:
        log_to_csv(csv_writer, iteration_id, "CREATE_TRANSACTION", {
            "status": "ERROR", 
            "error_message": "Failed to create transaction"
        })
        return
    
    # Eksperimen 1: Transaksi Original
    logger.info("🧪 EKSPERIMEN 1: Mengirim transaksi original ke Devnet...")
    original_result = send_transaction_with_balance_tracking(devnet_client, original_transaction_with_meta, sender_keypair, "Original")
    log_to_csv(csv_writer, iteration_id, "ORIGINAL_SEND", original_result)
    
    # Hanya lanjutkan jika transaksi original berhasil
    if original_result["status"] != "SUCCESS":
        logger.warning("⚠️ Transaksi original gagal, melewati eksperimen lainnya...")
        return
    
    original_signature = original_result["signature"]
    time.sleep(5)
    
    # Eksperimen 2: Direct Replay (Scientific Test)
    logger.info("🧪 EKSPERIMEN 2: Direct Replay dengan Signature Matching...")
    direct_replay_result = test_direct_replay(devnet_client, original_transaction_with_meta, sender_keypair, original_signature)
    log_to_csv(csv_writer, iteration_id, "DIRECT_REPLAY_SCIENTIFIC", direct_replay_result)
    
    time.sleep(5)
    
    # Eksperimen 3: Expired Replay (Deterministic Test)
    logger.info("🧪 EKSPERIMEN 3: Expired Replay dengan Slot Monitoring...")
    expired_replay_result = test_expired_replay(devnet_client, original_transaction_with_meta, sender_keypair)
    log_to_csv(csv_writer, iteration_id, "EXPIRED_REPLAY_DETERMINISTIC", expired_replay_result)
    
    # Eksperimen 4: Cross-Network Replay (Both Directions)
    logger.info("🧪 EKSPERIMEN 4A: Cross-Network Replay Devnet->Testnet...")
    cross_network_result_1 = test_cross_network_replay(devnet_client, testnet_client, original_transaction_with_meta, sender_keypair, "Devnet", "Testnet")
    log_to_csv(csv_writer, iteration_id, "CROSS_NETWORK_DEVNET_TO_TESTNET", cross_network_result_1)
    
    # Buat transaksi baru untuk arah sebaliknya
    time.sleep(5)
    testnet_transaction_with_meta = create_and_sign_transaction(testnet_client, sender_keypair, recipient_address)
    if testnet_transaction_with_meta:
        logger.info("🧪 EKSPERIMEN 4B: Cross-Network Replay Testnet->Devnet...")
        cross_network_result_2 = test_cross_network_replay(testnet_client, devnet_client, testnet_transaction_with_meta, sender_keypair, "Testnet", "Devnet")
        log_to_csv(csv_writer, iteration_id, "CROSS_NETWORK_TESTNET_TO_DEVNET", cross_network_result_2)
    
    logger.info(f"🎯 === EKSPERIMEN #{iteration_id} SELESAI ===")

def main(num_iterations=10):
    """Fungsi utama dengan pendekatan scientific experiment."""
    logger.info("🔬 Memulai Enhanced Solana Replay Attack Testing Suite...")
    logger.info(f"📊 Target iterasi: {num_iterations}")
    logger.info(f"📊 Total recipient wallets: {len(RECEIVER_WALLETS)}")
    
    # Setup clients dan keypair
    devnet_client, testnet_client = setup_clients()
    if not devnet_client or not testnet_client:
        logger.error("❌ FATAL: Gagal menginisialisasi clients. Program dihentikan.")
        return
    
    sender_keypair = load_keypair_from_config()
    if not sender_keypair:
        logger.error("❌ FATAL: Gagal memuat keypair. Program dihentikan.")
        return
    
    # Check initial balance
    initial_balance = get_balance(devnet_client, sender_keypair.pubkey())
    if initial_balance is None or initial_balance < 0.01:
        logger.error("❌ FATAL: Balance tidak mencukupi untuk testing. Minimum 0.01 SOL diperlukan.")
        return
    
    logger.info(f"✅ Initial balance check passed: {initial_balance:.6f} SOL")
    
    # Setup CSV logging
    try:
        with open(CSV_FILENAME, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
            csv_writer.writeheader()
            logger.info(f"📄 CSV file '{CSV_FILENAME}' initialized successfully.")
            
            # Main experiment loop
            for i in range(1, num_iterations + 1):
                # Pilih recipient wallet secara rotasi
                recipient_index = (i - 1) % len(RECEIVER_WALLETS)
                recipient_address = RECEIVER_WALLETS[recipient_index]
                
                logger.info(f"\n{'='*80}")
                logger.info(f"🚀 MEMULAI ITERASI {i}/{num_iterations}")
                logger.info(f"🎯 Target recipient: {recipient_address}")
                logger.info(f"{'='*80}")
                
                try:
                    # Jalankan siklus eksperimen lengkap
                    run_enhanced_experiment_cycle(
                        iteration_id=i,
                        devnet_client=devnet_client,
                        testnet_client=testnet_client,
                        sender_keypair=sender_keypair,
                        csv_writer=csv_writer,
                        recipient_address=recipient_address
                    )
                    
                    # Flush CSV after each iteration
                    csvfile.flush()
                    
                    logger.info(f"✅ Iterasi {i} berhasil diselesaikan.")
                    
                    # Cooldown period antara iterasi
                    if i < num_iterations:
                        logger.info("⏳ Cooldown period 15 detik sebelum iterasi berikutnya...")
                        time.sleep(15)
                        
                except KeyboardInterrupt:
                    logger.info("⚠️ Program dihentikan oleh user (Ctrl+C).")
                    break
                except Exception as e:
                    logger.error(f"❌ Error pada iterasi {i}: {e}")
                    # Log error ke CSV
                    log_to_csv(csv_writer, i, "ITERATION_ERROR", {
                        "status": "ITERATION_FAILED",
                        "error_message": str(e)
                    })
                    continue
    
    except Exception as e:
        logger.error(f"❌ FATAL ERROR saat setup CSV: {e}")
        return
    
    # Final summary
    logger.info(f"\n{'='*80}")
    logger.info("🎉 ENHANCED REPLAY ATTACK TESTING COMPLETED!")
    logger.info(f"📊 Total iterasi yang dijalankan: {min(i, num_iterations)}")
    logger.info(f"📄 Hasil lengkap tersimpan di: {CSV_FILENAME}")
    logger.info(f"📋 Log lengkap tersimpan di: enhanced_replay_attack.log")
    logger.info("🔬 Analisis data dapat dilakukan menggunakan tools seperti pandas/Excel.")
    logger.info(f"{'='*80}")

def print_usage():
    """Menampilkan panduan penggunaan program."""
    print("\n🔬 Enhanced Solana Replay Attack Tester")
    print("=====================================")
    print("Program ini melakukan pengujian ilmiah terhadap replay attack di Solana.")
    print("\nUsage:")
    print("  python enhanced_replay_tester.py [jumlah_iterasi]")
    print("\nExample:")
    print("  python enhanced_replay_tester.py 20")
    print("\nDefault: 10 iterasi")
    print("\nOutput files:")
    print("  - enhanced_replay_attack_log.csv: Data hasil eksperimen")
    print("  - enhanced_replay_attack.log: Log detail program")
    print("\nPersyaratan:")
    print("  - File config.py dengan WALLET_PRIVATE_KEY (base58)")
    print("  - Balance minimal 0.01 SOL di wallet untuk testing")
    print("  - Koneksi internet stabil")

if __name__ == "__main__":
    import sys
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help', 'help']:
            print_usage()
            sys.exit(0)
        try:
            num_iterations = int(sys.argv[1])
            if num_iterations <= 0:
                raise ValueError("Jumlah iterasi harus lebih dari 0")
        except ValueError as e:
            print(f"❌ Error: {e}")
            print("Gunakan: python enhanced_replay_tester.py [jumlah_iterasi_positif]")
            sys.exit(1)
    else:
        num_iterations = 10
    
    print("\n🔬 Enhanced Solana Replay Attack Testing Suite")
    print("=" * 50)
    print(f"🎯 Jumlah iterasi yang akan dijalankan: {num_iterations}")
    print(f"🌐 Target networks: Solana Devnet & Testnet")
    print(f"💼 Recipient wallets: {len(RECEIVER_WALLETS)} alamat")
    print("=" * 50)
    
    try:
        main(num_iterations)
    except KeyboardInterrupt:
        logger.info("\n⚠️ Program dihentikan oleh user.")
    except Exception as e:
        logger.error(f"\n❌ FATAL ERROR: {e}")
        sys.exit(1)