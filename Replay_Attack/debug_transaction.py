import asyncio
import base58
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.signature import Signature

try:
    import config
except ImportError:
    print("FATAL: File config.py tidak ditemukan.")
    exit()

async def debug_transaction_status():
    """Debug script untuk mengecek status transaksi yang suspicious."""
    
    # Setup client
    client = AsyncClient(f"https://solana-devnet.g.alchemy.com/v2/{config.ALCHEMY_API_KEY}")
    
    try:
        # Signature yang dicurigai
        suspicious_sig = "5nw7yRNG442v7MrCSzArZaccmBX2zYWeFTsp8xw2TggfFQFs7zpLyKFHxVkeCcGKsxp4MeMDn2WutYzDk4qJHmTd"
        
        print("🔍 DEBUGGING SUSPICIOUS TRANSACTION")
        print("=" * 50)
        print(f"🔑 Signature: {suspicious_sig}")
        print()
        
        # Convert ke Signature object
        sig_obj = Signature.from_string(suspicious_sig)
        
        # 1. Get transaction details
        print("1️⃣ Fetching transaction details...")
        tx_result = await client.get_transaction(
            sig_obj, 
            encoding="json",
            commitment="confirmed",
            max_supported_transaction_version=0
        )
        
        if tx_result.value:
            tx_data = tx_result.value
            print(f"✅ Transaction found!")
            print(f"   Slot: {tx_data.slot}")
            print(f"   Block Time: {tx_data.block_time}")
            print(f"   Success: {tx_data.transaction.meta.err is None}")
            
            # Check meta for more details
            meta = tx_data.transaction.meta
            print(f"   Fee: {meta.fee} lamports")
            print(f"   Pre Balances: {meta.pre_balances}")
            print(f"   Post Balances: {meta.post_balances}")
            
            # Calculate balance changes
            if len(meta.pre_balances) >= 2 and len(meta.post_balances) >= 2:
                sender_change = meta.post_balances[0] - meta.pre_balances[0]
                recipient_change = meta.post_balances[1] - meta.pre_balances[1]
                print(f"   Sender Balance Change: {sender_change} lamports")
                print(f"   Recipient Balance Change: {recipient_change} lamports")
            
        else:
            print("❌ Transaction NOT found in ledger!")
            print("   This could mean:")
            print("   - Transaction was never actually executed")
            print("   - RPC returned success but transaction failed")
            print("   - Network/timing issue")
        
        print()
        
        # 2. Get signature status
        print("2️⃣ Checking signature status...")
        status_result = await client.get_signature_status(sig_obj)
        
        if status_result.value:
            status = status_result.value
            print(f"✅ Status found!")
            print(f"   Confirmations: {status.confirmations}")
            print(f"   Error: {status.err}")
            print(f"   Confirmation Status: {status.confirmation_status}")
        else:
            print("❌ No status found!")
        
        print()
        
        # 3. Check current wallet balance
        print("3️⃣ Checking current wallet balance...")
        private_key_bytes = base58.b58decode(config.WALLET_PRIVATE_KEY)
        keypair = Keypair.from_bytes(private_key_bytes)
        
        balance = await client.get_balance(keypair.pubkey())
        print(f"💰 Current wallet balance: {balance.value / 1e9:.6f} SOL")
        
        print()
        print("🤔 ANALYSIS:")
        if tx_result.value and tx_result.value.transaction.meta.err is None:
            print("✅ Transaction was ACTUALLY executed successfully")
            print("⚠️  This confirms the race condition vulnerability!")
            print("💡 Multiple identical transactions were processed")
        else:
            print("❌ Transaction failed or wasn't executed")
            print("💡 RPC might have returned false positive success")
        
    except Exception as e:
        print(f"❌ Error during debugging: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(debug_transaction_status())