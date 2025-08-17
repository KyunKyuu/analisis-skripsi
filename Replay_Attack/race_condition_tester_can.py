import argparse
import csv
import asyncio
import logging
import base58
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

try:
    import config
except ImportError:
    print("FATAL: File config.py tidak ditemukan.")
    exit()

# Solana imports
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.message import Message
from solders.transaction import VersionedTransaction
from solana.rpc.core import RPCException
from solana.rpc.types import TxOpts

# === Konfigurasi ===
TRANSFER_AMOUNT_LAMPORTS = 5000000  # 0.005 SOL
RECIPIENT_ADDRESS = None  # None = self-transfer
CSV_FILENAME = "race_condition_summary.csv"
CSV_HEADERS = [
    "timestamp_utc", "run_id", "task_id", "submission_status", 
    "returned_signature", "submission_response", "submission_timing_ms"
]

# Global variables
NUM_CONCURRENT_REQUESTS = 10
DEVNET_RPC_URL = ""
CONFIRMATION_TIMEOUT = 30  # seconds

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('race_condition_experiment.log', 'w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def setup_client() -> AsyncClient:
    """Setup Solana RPC client."""
    try:
        client = AsyncClient(DEVNET_RPC_URL)
        await client.get_slot()  # Test connection
        logger.info(f"✅ Connected to: {DEVNET_RPC_URL}")
        return client
    except Exception as e:
        logger.error(f"❌ Connection failed: {e}")
        raise

def load_keypair_from_config() -> Keypair:
    """Load keypair from config.py."""
    try:
        if not hasattr(config, 'WALLET_PRIVATE_KEY') or not config.WALLET_PRIVATE_KEY:
            raise ValueError("WALLET_PRIVATE_KEY not found in config.py")
        
        private_key_bytes = base58.b58decode(config.WALLET_PRIVATE_KEY)
        sender_keypair = Keypair.from_bytes(private_key_bytes)
        logger.info(f"✅ Keypair loaded: {sender_keypair.pubkey()}")
        return sender_keypair
    except Exception as e:
        logger.error(f"❌ Failed to load keypair: {e}")
        raise

async def create_signed_transaction(client: AsyncClient, sender_keypair: Keypair, recipient_address: str) -> VersionedTransaction:
    """Create and sign a transfer transaction with fresh blockhash."""
    try:
        recipient_pubkey = Pubkey.from_string(recipient_address)
        
        # Get fresh blockhash
        blockhash_resp = await client.get_latest_blockhash(commitment="confirmed")
        if not blockhash_resp.value:
            raise Exception("Failed to get blockhash")
        
        blockhash = blockhash_resp.value.blockhash
        logger.info(f"🔗 Using blockhash: {blockhash}")
        
        # Create transfer instruction
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=sender_keypair.pubkey(),
                to_pubkey=recipient_pubkey,
                lamports=TRANSFER_AMOUNT_LAMPORTS
            )
        )
        
        # Create transaction
        message = Message.new_with_blockhash([transfer_instruction], sender_keypair.pubkey(), blockhash)
        transaction = VersionedTransaction(message, [sender_keypair])
        
        logger.info(f"✅ Transaction created for {recipient_address}")
        logger.info(f"📝 Unique Signature: {transaction.signatures[0]}")
        return transaction
        
    except Exception as e:
        logger.error(f"❌ Failed to create transaction: {e}")
        raise

async def submission_worker(client: AsyncClient, transaction: VersionedTransaction, task_id: int, run_id: str, barrier: asyncio.Barrier) -> Dict[str, Any]:
    """Submit transaction and log individual task result."""
    timestamp_utc = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    original_signature = str(transaction.signatures[0])
    
    submission_result = {
        "timestamp_utc": timestamp_utc,
        "run_id": run_id,
        "task_id": task_id,
        "submission_status": "PENDING",
        "returned_signature": original_signature,
        "submission_response": "",
        "submission_timing_ms": 0
    }
    
    try:
        # Wait at barrier for synchronized submission
        await barrier.wait()
        
        submission_start = time.time()
        logger.info(f"📤 Task {task_id}: SUBMITTED with signature {original_signature}")
        
        # Submit transaction
        tx_opts = TxOpts(
            skip_preflight=True,
            preflight_commitment="processed",
            max_retries=0
        )
        
        send_result = await client.send_transaction(transaction, opts=tx_opts)
        submission_end = time.time()
        timing_ms = round((submission_end - submission_start) * 1000, 2)
        
        if hasattr(send_result, 'value') and send_result.value:
            returned_signature = str(send_result.value)
            submission_result.update({
                "submission_status": "ACCEPTED",
                "returned_signature": returned_signature,
                "submission_response": f"RPC accepted: {returned_signature}",
                "submission_timing_ms": timing_ms
            })
        else:
            submission_result.update({
                "submission_status": "NO_SIGNATURE",
                "submission_response": "RPC did not return signature",
                "submission_timing_ms": timing_ms
            })
            
    except RPCException as rpc_err:
        error_msg = str(rpc_err)
        
        # Classify RPC errors
        if any(keyword in error_msg.lower() for keyword in [
            "duplicate", "already processed", "already in the ledger",
            "transaction already exists", "already been processed"
        ]):
            status = "DUPLICATE_REJECTED"
        elif "blockhash not found" in error_msg.lower():
            status = "BLOCKHASH_EXPIRED"
        else:
            status = "RPC_ERROR"
        
        submission_result.update({
            "submission_status": status,
            "submission_response": error_msg,
            "submission_timing_ms": round((time.time() - submission_start) * 1000, 2)
        })
        
    except Exception as e:
        submission_result.update({
            "submission_status": "UNEXPECTED_ERROR",
            "submission_response": str(e),
            "submission_timing_ms": 0
        })
    
    return submission_result

async def check_final_confirmation(client: AsyncClient, signature_str: str) -> tuple[str, float]:
    """Check final blockchain confirmation status for the unique signature."""
    logger.info(f"🔍 Finalization check for {signature_str}...")
    
    try:
        signature_obj = Signature.from_string(signature_str)
        confirmation_start = time.time()
        
        # Check confirmation with timeout
        while time.time() - confirmation_start < CONFIRMATION_TIMEOUT:
            try:
                status_resp = await client.get_signature_statuses([signature_obj], search_transaction_history=True)
                
                if status_resp.value and len(status_resp.value) > 0:
                    status_info = status_resp.value[0]
                    if status_info:
                        if status_info.confirmation_status:
                            confirmation_time = round((time.time() - confirmation_start) * 1000, 2)
                            if status_info.err:
                                return "TRANSACTION_FAILED", confirmation_time
                            else:
                                return "CONFIRMED", confirmation_time
                    else:
                        return "NOT_FOUND", round((time.time() - confirmation_start) * 1000, 2)
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.warning(f"⚠️ Error during confirmation check: {e}")
                await asyncio.sleep(1)
        
        return "TIMEOUT", round((time.time() - confirmation_start) * 1000, 2)
        
    except Exception as e:
        logger.error(f"❌ Confirmation error: {e}")
        return "ERROR", 0

async def check_wallet_balance(client: AsyncClient, sender_keypair: Keypair):
    """Check wallet balance and request airdrop if needed."""
    try:
        balance = (await client.get_balance(sender_keypair.pubkey())).value
        logger.info(f"💰 Current balance: {balance / 1e9:.6f} SOL")
        
        total_needed = NUM_CONCURRENT_REQUESTS * TRANSFER_AMOUNT_LAMPORTS + 10000000
        
        if balance < total_needed:
            logger.info(f"💧 Requesting airdrop...")
            airdrop_amount = int(2.0 * 1e9)
            resp = await client.request_airdrop(sender_keypair.pubkey(), airdrop_amount)
            
            if resp.value:
                logger.info(f"✅ Airdrop requested: {resp.value}")
                await asyncio.sleep(20)
                balance = (await client.get_balance(sender_keypair.pubkey())).value
                logger.info(f"💰 Balance after airdrop: {balance / 1e9:.6f} SOL")
                
    except Exception as e:
        logger.error(f"❌ Balance check failed: {e}")

def write_results_to_csv(results: List[Dict[str, Any]]):
    """Write submission results to CSV file."""
    try:
        with open(CSV_FILENAME, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
            writer.writeheader()
            writer.writerows(results)
        logger.info(f"📄 Submission results written to {CSV_FILENAME}")
    except Exception as e:
        logger.error(f"❌ CSV write failed: {e}")

def print_experiment_summary(run_id: str, unique_signature: str, submission_results: List[Dict[str, Any]], 
                           final_status: str, confirmation_time_ms: float):
    """Print comprehensive experiment summary."""
    
    # Count submission results
    total_requests = len(submission_results)
    accepted_count = sum(1 for r in submission_results if r["submission_status"] == "ACCEPTED")
    duplicate_rejected = sum(1 for r in submission_results if r["submission_status"] == "DUPLICATE_REJECTED")
    failed_count = total_requests - accepted_count - duplicate_rejected
    
    # Determine blockchain confirmations
    blockchain_confirmations = 1 if final_status == "CONFIRMED" else 0
    rejected_duplicates = accepted_count - blockchain_confirmations
    
    print("\n" + "=" * 60)
    print("              RACE CONDITION TEST SUMMARY")
    print("=" * 60)
    print(f"Run ID: {run_id}")
    print(f"Total Requests Sent: {total_requests}")
    print(f"Unique Signature: {unique_signature}")
    print()
    print("Submission Results:")
    print(f"- RPC Accepted: {accepted_count}")
    print(f"- RPC Rejected as Duplicate: {duplicate_rejected}")
    print(f"- Failed to Submit: {failed_count}")
    print()
    print("Final Blockchain Status:")
    if final_status == "CONFIRMED":
        print(f"- ✅ SUCCESS: Signature {unique_signature} was confirmed on-chain")
        print(f"- Confirmation Time: {confirmation_time_ms:.2f} ms")
    elif final_status == "NOT_FOUND":
        print(f"- ❌ NOT FOUND: Signature was not found on blockchain")
    elif final_status == "TRANSACTION_FAILED":
        print(f"- ❌ FAILED: Transaction failed on blockchain")
    elif final_status == "TIMEOUT":
        print(f"- ⏰ TIMEOUT: Confirmation check timed out after {CONFIRMATION_TIMEOUT}s")
    else:
        print(f"- ❓ UNKNOWN: Final status = {final_status}")
    print()
    print("Outcome:")
    print(f"- Blockchain Confirmations: {blockchain_confirmations}")
    print(f"- Rejected Duplicates: {rejected_duplicates}")
    print()
    
    # Final conclusion
    print("Conclusion:", end=" ")
    if accepted_count > 0 and blockchain_confirmations == 1:
        print("SUCCESS. The Solana network correctly processed only one")
        print("            of the {} identical concurrent transactions, proving its".format(accepted_count))
        print("            resistance to race condition duplicate attacks.")
    elif accepted_count > 0 and blockchain_confirmations == 0:
        print("PARTIAL. RPC accepted transactions but none confirmed.")
        print("            This may indicate network issues or blockhash expiry.")
    elif blockchain_confirmations > 1:
        print("CRITICAL. Multiple identical transactions were confirmed!")
        print("            This suggests a serious duplicate protection failure!")
    elif duplicate_rejected == total_requests - 1:
        print("EXCELLENT. RPC nodes immediately rejected duplicates,")
        print("            showing strong preliminary duplicate protection.")
    else:
        print("INCONCLUSIVE. Mixed results require further analysis.")
    
    print("=" * 60)

async def main():
    """Main experiment function."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    logger.info(f"🚀 Starting Race Condition Experiment - Run ID: {run_id}")
    
    client = None
    try:
        # Setup
        client = await setup_client()
        sender_keypair = load_keypair_from_config()
        
        # Determine recipient
        recipient_addr = RECIPIENT_ADDRESS if RECIPIENT_ADDRESS else str(sender_keypair.pubkey())
        logger.info(f"🎯 Target recipient: {recipient_addr}")
        
        # Check wallet balance
        await check_wallet_balance(client, sender_keypair)
        
        # Create the transaction to be tested
        logger.info("🔨 Creating transaction for race condition test...")
        race_transaction = await create_signed_transaction(client, sender_keypair, recipient_addr)
        unique_signature = str(race_transaction.signatures[0])
        
        logger.info(f"📋 Experiment setup complete:")
        logger.info(f"   🔑 Unique Signature: {unique_signature}")
        logger.info(f"   📤 Will be submitted {NUM_CONCURRENT_REQUESTS} times concurrently")
        
        # === PHASE 1: CONCURRENT SUBMISSION ===
        logger.info("=" * 50)
        logger.info("📤 PHASE 1: CONCURRENT SUBMISSION")
        logger.info("=" * 50)
        
        barrier = asyncio.Barrier(NUM_CONCURRENT_REQUESTS)
        submission_tasks = []
        
        for task_id in range(1, NUM_CONCURRENT_REQUESTS + 1):
            task = submission_worker(client, race_transaction, task_id, run_id, barrier)
            submission_tasks.append(task)
        
        logger.info(f"🚀 Launching {NUM_CONCURRENT_REQUESTS} concurrent submissions...")
        submission_results = await asyncio.gather(*submission_tasks, return_exceptions=True)
        
        # Process submission results
        processed_results = []
        for i, result in enumerate(submission_results):
            if isinstance(result, Exception):
                logger.error(f"❌ Task {i+1} exception: {result}")
                processed_results.append({
                    "timestamp_utc": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    "run_id": run_id,
                    "task_id": i+1,
                    "submission_status": "EXCEPTION",
                    "returned_signature": unique_signature,
                    "submission_response": str(result),
                    "submission_timing_ms": 0
                })
            else:
                processed_results.append(result)
        
        logger.info("📊 Submission phase complete")
        
        # === PHASE 2: SINGLE FINALIZATION CHECK ===
        logger.info("=" * 50)
        logger.info("🔍 PHASE 2: FINALIZATION CHECK")
        logger.info("=" * 50)
        
        # Wait a moment for network processing
        logger.info("⏳ Waiting 5 seconds for network processing...")
        await asyncio.sleep(5)
        
        # Check final status of the unique signature
        final_status, confirmation_time_ms = await check_final_confirmation(client, unique_signature)
        
        if final_status == "CONFIRMED":
            logger.info(f"✅ SUCCESS: Signature {unique_signature} was confirmed on-chain")
        elif final_status == "NOT_FOUND":
            logger.info(f"❌ NOT FOUND: Signature was not found on blockchain")
        elif final_status == "TRANSACTION_FAILED":
            logger.info(f"❌ FAILED: Transaction failed on blockchain")
        elif final_status == "TIMEOUT":
            logger.info(f"⏰ TIMEOUT: Confirmation check timed out")
        else:
            logger.info(f"❓ UNKNOWN: Final status = {final_status}")
        
        # === SAVE RESULTS AND DISPLAY SUMMARY ===
        write_results_to_csv(processed_results)
        print_experiment_summary(run_id, unique_signature, processed_results, final_status, confirmation_time_ms)
        
    except Exception as e:
        logger.error(f"❌ FATAL ERROR: {e}", exc_info=True)
    finally:
        if client:
            await client.close()
        logger.info("🎉 Race Condition Experiment Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Solana Race Condition Experiment - Optimized Version")
    parser.add_argument(
        '--rpc', 
        dest='rpc_provider', 
        choices=['alchemy', 'helius', 'local', 'devnet'], 
        required=True, 
        help="Choose RPC provider"
    )
    parser.add_argument(
        '-n', 
        '--requests', 
        dest='num_requests', 
        type=int, 
        default=5,
        help="Number of concurrent requests (default: 5)"
    )
    parser.add_argument(
        '--timeout',
        dest='confirmation_timeout',
        type=int,
        default=30,
        help="Confirmation timeout in seconds (default: 30)"
    )
    args = parser.parse_args()
    
    NUM_CONCURRENT_REQUESTS = args.num_requests
    CONFIRMATION_TIMEOUT = args.confirmation_timeout
    
    # Set RPC URL
    if args.rpc_provider == 'helius':
        if not hasattr(config, 'HELIUS_API_KEY') or not config.HELIUS_API_KEY:
            print("FATAL: HELIUS_API_KEY not found in config.py")
            exit()
        DEVNET_RPC_URL = f"https://devnet.helius-rpc.com/?api-key={config.HELIUS_API_KEY}"
    elif args.rpc_provider == 'alchemy':
        if not hasattr(config, 'ALCHEMY_API_KEY') or not config.ALCHEMY_API_KEY:
            print("FATAL: ALCHEMY_API_KEY not found in config.py")
            exit()
        DEVNET_RPC_URL = f"https://solana-devnet.g.alchemy.com/v2/{config.ALCHEMY_API_KEY}"
    elif args.rpc_provider == 'local':
        DEVNET_RPC_URL = "http://127.0.0.1:8899"
        print("⚠️  WARNING: Local validator may not enforce proper duplicate transaction protection!")
        print("💡 For accurate results, consider using --rpc helius or --rpc alchemy")
    elif args.rpc_provider == 'devnet':
        DEVNET_RPC_URL = "https://api.devnet.solana.com/"
    else:
        print("FATAL: Invalid RPC provider selected.")
        exit()
    
    asyncio.run(main())