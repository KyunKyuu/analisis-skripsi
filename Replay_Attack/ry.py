import argparse
import time
from base64 import b64decode
import base58
import config
from typing import Optional, List
from solders.transaction import VersionedTransaction
from solders.message import Message
from solders.transaction import Transaction as LegacyTransaction

# Solana imports
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams, transfer
from solders.hash import Hash
from solders.instruction import Instruction, CompiledInstruction
from solana.rpc.commitment import Confirmed


# === Configuration ===
PHANTOM_SIGNATURE = "t4Rr8T1LFxgMU7ksd7NRtt4mQxZ8agTFmmbz5njHhVGkiQbd4DvHfB2xXK5qab8kQ479NpKWh2ZuqrCaw5sszRW"
MODIFIED_RECEIVER = "44SQNhw9mQ5ArLLCQqZAkGiAWY1vHEhMouGK4FFfWaJY"
LAMPORTS = 1000

# === Solana Clients ===
devnet_client = Client("https://api.devnet.solana.com")
testnet_client = Client("https://api.testnet.solana.com")

# === Utility Functions ===

def request_devnet_airdrop(client: Client, pubkey: Pubkey, amount_sol: float = 1.0):
    """Request airdrop on devnet"""
    try:
        lamports = int(amount_sol * 1e9)
        response = client.request_airdrop(pubkey, lamports)
        if hasattr(response, 'value'):
            print(f"✅ Airdrop requested: {response.value}")
            print("⏳ Waiting 10 seconds for airdrop confirmation...")
            time.sleep(10)
            return True
        else:
            print(f"❌ Airdrop failed: {response}")
            return False
    except Exception as e:
        print(f"❌ Airdrop error: {e}")
        return False

def check_wallet_balance(client: Client, pubkey: Pubkey) -> Optional[float]:
    """Check wallet balance in SOL"""
    try:
        balance_resp = client.get_balance(pubkey)
        if balance_resp.value is not None:
            balance_sol = balance_resp.value / 1e9  # Convert lamports to SOL
            return balance_sol
        return None
    except Exception as e:
        print(f"Error checking balance: {e}")
        return None

def get_transaction_info(client: Client, signature: str) -> Optional[dict]:
    """Get transaction info"""
    try:
        sig_obj = Signature.from_string(signature)
        resp = client.get_transaction(sig_obj, encoding="jsonParsed", max_supported_transaction_version=0)
        
        if resp.value is None:
            print("❌ Transaction not found")
            return None

        tx = resp.value.transaction.transaction
        message = tx.message
        
        info = {
            "blockhash": message.recent_blockhash,
            "sender": str(message.account_keys[0].pubkey),
            "signature": str(tx.signatures[0])
        }
        
        print("✅ Transaction info retrieved")
        return info
    except Exception as e:
        print(f"Error getting transaction info: {e}")
        return None

def get_raw_tx(client: Client, signature: str) -> Optional[VersionedTransaction]:
    """Get transaction as VersionedTransaction object"""
    try:
        sig_obj = Signature.from_string(signature)
        resp = client.get_transaction(
            sig_obj,
            encoding="base64",
            max_supported_transaction_version=0
        )

        if resp.value is None:
            print("❌ Failed to get transaction")
            return None

        tx_data = resp.value.transaction.transaction

        if isinstance(tx_data, VersionedTransaction):
            print("Debug: Transaction data is already VersionedTransaction.")
            return tx_data
        elif isinstance(tx_data, str):
            print("Debug: Transaction data is a string, attempting base64 decode.")
            try:
                tx_bytes = b64decode(tx_data)
                versioned_tx = VersionedTransaction.from_bytes(tx_bytes)
                return versioned_tx
            except Exception as decode_err:
                print(f"Error decoding base64 or creating from bytes: {decode_err}")
                return None
        else:
            print(f"Debug: Unexpected type for transaction data: {type(tx_data)}")
            return None

    except Exception as e:
        print(f"Error getting transaction: {str(e)}")
        return None

def replay_transaction_direct(client: Client, original_tx: VersionedTransaction, label: str):
    """Send original transaction directly (for immediate replay test)"""
    print(f"\n🔁 [REPLAY - {label}] Sending original transaction...")
    try:
        # Try to send the original transaction as-is
        result = client.send_transaction(original_tx)
        
        if hasattr(result, 'value'):
            print(f"✅ REPLAY SUCCESSFUL (UNEXPECTED): {result.value}")
        else:
            print(f"✅ REPLAY SUCCESSFUL (UNEXPECTED): {result}")
    except Exception as e:
        print(f"❌ REPLAY REJECTED (EXPECTED): {e}")

def create_signed_transaction(
    client: Client,
    instructions: List[Instruction],
    payer: Pubkey,
    signers: List[Keypair]
) -> Optional[VersionedTransaction]:
    """Create and sign a new VersionedTransaction"""
    try:
        # Get recent blockhash
        blockhash_resp = client.get_latest_blockhash(commitment=Confirmed)
        if blockhash_resp.value is None:
            print("❌ Failed to get recent blockhash")
            return None

        blockhash = blockhash_resp.value.blockhash
        
        # Create message
        message = Message.new_with_blockhash(
            instructions,
            payer,
            blockhash
        )
        
        # Create transaction
        tx = VersionedTransaction(message, signers)
        return tx
    except Exception as e:
        print(f"❌ Failed to create transaction: {e}")
        return None

def test_replay_attack_original(raw_tx: VersionedTransaction):
    """Test immediate replay of original transaction"""
    print("\n=== [1] Replay Langsung (Original Transaction) ===")
    replay_transaction_direct(devnet_client, raw_tx, "Langsung ke Devnet")

def test_replay_with_expired_blockhash(raw_tx: VersionedTransaction):
    """Test replay after blockhash expires"""
    print("\n=== [2] Replay Setelah Blockhash Kedaluwarsa ===")
    print("⏳ Menunggu 120 detik agar blockhash kedaluwarsa...")
    time.sleep(120)
    replay_transaction_direct(devnet_client, raw_tx, "Expired Blockhash")

def test_replay_cross_chain(raw_tx: VersionedTransaction):
    """Test cross-chain replay"""
    print("\n=== [3] Cross-Chain Replay (Devnet ke Testnet) ===")
    replay_transaction_direct(testnet_client, raw_tx, "Cross-chain ke Testnet")

def test_replay_with_modified_data():
    """Test replay with modified receiver"""
    print("\n=== [4] Replay with Modified Data (Receiver) ===")
    try:
        sender = Keypair.from_bytes(base58.b58decode(config.WALLET_PRIVATE_KEY))
        
        # Check balance first
        balance = check_wallet_balance(devnet_client, sender.pubkey())
        if balance is None:
            print("❌ Could not check wallet balance")
            return
            
        print(f"💰 Wallet balance: {balance:.4f} SOL")
        
        if balance < 0.001:
            print("💰 Requesting devnet airdrop...")
            if request_devnet_airdrop(devnet_client, sender.pubkey(), 1.0):
                balance = check_wallet_balance(devnet_client, sender.pubkey())
                print(f"💰 New balance: {balance:.4f} SOL")
            else:
                print("❌ Failed to get airdrop")
                return
        
        # Create new transaction with modified receiver
        modified_receiver = Pubkey.from_string(MODIFIED_RECEIVER)
        
        # First create the recipient account if needed
        recipient_info = devnet_client.get_account_info(modified_receiver)
        if recipient_info.value is None:
            # Need to include account creation lamports (minimum rent exemption)
            create_account_ix = transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(),
                    to_pubkey=modified_receiver,
                    lamports=1000000  # Enough for rent exemption (~0.001 SOL)
                )
            )
            transfer_ix = transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(),
                    to_pubkey=modified_receiver,
                    lamports=LAMPORTS
                )
            )
            instructions = [create_account_ix, transfer_ix]
        else:
            instructions = [transfer(
                TransferParams(
                    from_pubkey=sender.pubkey(),
                    to_pubkey=modified_receiver,
                    lamports=LAMPORTS
                )
            )]
        
        # Create and sign transaction
        signed_tx = create_signed_transaction(
            devnet_client,
            instructions,
            sender.pubkey(),
            [sender]
        )
        
        if signed_tx is None:
            print("❌ Failed to create modified transaction")
            return

        result = devnet_client.send_transaction(signed_tx)
        
        if hasattr(result, 'value'):
            print(f"✅ MODIFIED DATA TRANSACTION SENT: {result.value}")
        else:
            print(f"✅ MODIFIED DATA TRANSACTION SENT: {result}")
            
    except Exception as e:
        print(f"❌ Modified Data Replay FAILED: {e}")

def test_create_and_replay():
    """Create a fresh transaction and then try to replay it"""
    print("\n=== [5] Create Fresh Transaction and Replay ===")
    
    try:
        # Check wallet balance first
        sender = Keypair.from_bytes(base58.b58decode(config.WALLET_PRIVATE_KEY))
        balance = check_wallet_balance(devnet_client, sender.pubkey())
        
        if balance is None:
            print("❌ Could not check wallet balance")
            return
            
        print(f"💰 Wallet balance: {balance:.4f} SOL")
        
        if balance < 0.001:
            print("💰 Requesting devnet airdrop...")
            if request_devnet_airdrop(devnet_client, sender.pubkey(), 1.0):
                balance = check_wallet_balance(devnet_client, sender.pubkey())
                print(f"💰 New balance: {balance:.4f} SOL")
            else:
                print("❌ Failed to get airdrop")
                return
        
        # Define recipient (use a new address each time)
        recipient = Keypair().pubkey()
        
        # First create the recipient account
        create_account_ix = transfer(
            TransferParams(
                from_pubkey=sender.pubkey(),
                to_pubkey=recipient,
                lamports=1000000  # Enough for rent exemption
            )
        )
        
        # Then transfer some lamports
        transfer_ix = transfer(
            TransferParams(
                from_pubkey=sender.pubkey(),
                to_pubkey=recipient,
                lamports=LAMPORTS
            )
        )
        
        # First create a fresh transaction
        fresh_tx = create_signed_transaction(
            devnet_client,
            [create_account_ix, transfer_ix],
            sender.pubkey(),
            [sender]
        )
        
        if fresh_tx is None:
            print("❌ Failed to create fresh transaction")
            return

        # Send the fresh transaction
        result = devnet_client.send_transaction(fresh_tx)
        
        if hasattr(result, 'value'):
            print(f"✅ FRESH TRANSACTION SENT: {result.value}")
        else:
            print(f"✅ FRESH TRANSACTION SENT: {result}")
        
        print("\n⏳ Waiting 15 seconds before replay attempt...")
        time.sleep(15)  # Wait longer to ensure blockhash expires
        
        # Try to replay the fresh transaction
        replay_transaction_direct(devnet_client, fresh_tx, "Fresh Transaction Replay")
            
    except Exception as e:
        print(f"❌ Error in create and replay test: {e}")

# === Main Execution ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Replay Attack on Solana Devnet")
    parser.add_argument("--test", 
                       choices=["original", "expired", "cross", "modified", "fresh", "all"], 
                       required=True, 
                       help="Type of replay test")
    args = parser.parse_args()

    print("=== Solana Replay Attack Test ===")
   
    
    raw_tx_to_replay = None
    if args.test in ["original", "expired", "cross", "all"]:
        print(f"\n📡 Fetching transaction: {PHANTOM_SIGNATURE}")
        
        info = get_transaction_info(devnet_client, PHANTOM_SIGNATURE)
        if not info:
            print("❌ Gagal mendapatkan info transaksi awal")
            if args.test == "all":
                print("🔄 Melanjutkan dengan test lainnya...")
            else:
                exit("Pengujian dihentikan.")

        if info:
            print("\n📄 TRANSACTION INFO:")
            print(f"• Signature   : {info['signature']}")
            print(f"• Sender      : {info['sender']}")
            print(f"• Blockhash   : {info['blockhash']}")
            
            raw_tx_to_replay = get_raw_tx(devnet_client, PHANTOM_SIGNATURE)
            if not raw_tx_to_replay:
                print("❌ Gagal mendapatkan data transaksi mentah")
                if args.test != "all":
                    exit("Pengujian dihentikan.")

    # Run tests based on argument
    if args.test == "original" or args.test == "all":
        if raw_tx_to_replay:
            test_replay_attack_original(raw_tx_to_replay)
        else:
            print("⚠️  Skipping original replay test - no transaction data")
                    
    if args.test == "cross" or args.test == "all":
        if raw_tx_to_replay:
            test_replay_cross_chain(raw_tx_to_replay)
        else:
            print("⚠️  Skipping cross-chain replay test - no transaction data")
            
    if args.test == "modified" or args.test == "all":
        test_replay_with_modified_data()

    if args.test == "expired" or args.test == "all":
        if raw_tx_to_replay:
            test_replay_with_expired_blockhash(raw_tx_to_replay)
        else:
            print("⚠️  Skipping expired replay test - no transaction data")    
        
    if args.test == "fresh" or args.test == "all":
        test_create_and_replay()
        
    print("\n=== Test Completed ===")
