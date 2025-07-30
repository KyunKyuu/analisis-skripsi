#!/usr/bin/env python3
"""
Enhanced Ed25519 Signature Malleability Tester with Iterative Testing
Test Scenarios:
A. Standard Malleability (S' = L - S)
B. Non-Canonical Signature (S'' = S + L) 
C. R Component Manipulation (Modified R)

Usage: python mallabelity_tester.py [iterations]
Default: 100 iterations if no argument provided
"""

import csv
import datetime
import logging
import os
import random
import sys
import time
from typing import Tuple, Optional, Dict, List
from enum import Enum

from solana.rpc.api import Client
from solana.rpc.commitment import Commitment
from solders.transaction import Transaction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import VersionedTransaction
from solders.message import MessageV0, to_bytes_versioned
from solders.signature import Signature
from solders.hash import Hash

# Import private key from config.py
try:
    from config import WALLET_PRIVATE_KEY
except ImportError:
    print("ERROR: Could not import WALLET_PRIVATE_KEY from config.py")
    print("Please create config.py with your private key:")
    exit(1)

# Ed25519 curve order constant as per RFC 8032
L = 2**252 + 27742317777372353535851937790883648493

class TestScenario(Enum):
    """Enumeration of different malleability test scenarios."""
    SCENARIO_A = "Standard_Malleability_S_Prime"
    SCENARIO_B = "Non_Canonical_S_Plus_L"
    SCENARIO_C = "R_Component_Manipulation"

class TestResult(Enum):
    """Enumeration of possible test results."""
    REJECTED_AS_EXPECTED = "REJECTED_AS_EXPECTED"
    FAILED_UNEXPECTEDLY_ACCEPTED = "FAILED_UNEXPECTEDLY_ACCEPTED" 
    ERROR = "ERROR"
    CONSTRUCTION_FAILED = "CONSTRUCTION_FAILED"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedMalleabilityTester:
    """
    Enhanced class to comprehensively test Ed25519 signature malleability 
    on Solana Devnet across multiple attack vectors with iterative testing.
    """
    
    def __init__(self, iterations: int = 100):
        """Initialize the enhanced malleability tester with iteration count."""
        self.rpc_client = Client(
            "https://solana-devnet.g.alchemy.com/v2/H4UsVfnsrnMYIXz5ECoM2", 
            commitment=Commitment("confirmed")
        )
        self.sender_keypair = self._load_keypair()
        self.iterations = iterations
        self.csv_filename = f"malleability_test_log_{iterations}_iterations_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._setup_csv_logging()
        self.test_results: List[Dict] = []
        
        # Statistics tracking
        self.total_tests_run = 0
        self.total_passed = 0
        self.total_failed = 0
        self.scenario_stats = {
            TestScenario.SCENARIO_A: {"passed": 0, "failed": 0, "errors": 0},
            TestScenario.SCENARIO_B: {"passed": 0, "failed": 0, "errors": 0},
            TestScenario.SCENARIO_C: {"passed": 0, "failed": 0, "errors": 0}
        }
    
    def _load_keypair(self) -> Keypair:
        """Load keypair from the imported private key."""
        try:
            if isinstance(WALLET_PRIVATE_KEY, str):
                return Keypair.from_base58_string(WALLET_PRIVATE_KEY)
            elif isinstance(WALLET_PRIVATE_KEY, (list, bytes)):
                return Keypair.from_bytes(WALLET_PRIVATE_KEY)
            else:
                raise ValueError("Invalid private key format")
        except Exception as e:
            logger.error(f"Failed to load keypair: {e}")
            raise
    
    def _setup_csv_logging(self):
        """Setup CSV file for logging comprehensive test results."""
        if not os.path.exists(self.csv_filename):
            with open(self.csv_filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    'iteration_number',
                    'timestamp_utc',
                    'test_scenario',
                    'original_signature_hex',
                    'manipulated_signature_hex',
                    'manipulation_description',
                    'status',
                    'rpc_response_message',
                    'expected_result',
                    'test_passed',
                    'transaction_destination',
                    'amount_lamports'
                ])
    
    def _log_test_result(self, iteration: int, scenario: TestScenario, original_sig: str, 
                        manipulated_sig: str, manipulation_desc: str,
                        status: TestResult, rpc_message: str, test_passed: bool,
                        destination: str = "", amount: int = 0):
        """Log comprehensive test results to CSV file."""
        with open(self.csv_filename, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                iteration,
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
                scenario.value,
                original_sig,
                manipulated_sig,
                manipulation_desc,
                status.value,
                rpc_message,
                "REJECTED",  # We always expect rejection
                test_passed,
                destination,
                amount
            ])
    
    def create_original_transaction(self) -> Tuple[VersionedTransaction, bytes, str, int]:
        """
        Create a legitimate test transaction that will serve as the basis 
        for all malleability tests.
        
        Returns:
            Tuple[VersionedTransaction, bytes, str, int]: Original signed transaction, 
            signature bytes, destination address, and amount
        """
        # Generate a random destination address for the transfer
        destination = Keypair().pubkey()
        
        # Random amount between 0.001 and 0.01 SOL (1,000,000 to 10,000,000 lamports)
        amount_lamports = random.randint(1_000_000, 10_000_000)

        # Create transfer instruction
        transfer_instruction = transfer(
            TransferParams(
                from_pubkey=self.sender_keypair.pubkey(),
                to_pubkey=destination,
                lamports=amount_lamports
            )
        )

        # Get recent blockhash
        recent_blockhash_response = self.rpc_client.get_latest_blockhash()
        recent_blockhash = recent_blockhash_response.value.blockhash

        # Create message for versioned transaction
        message = MessageV0.try_compile(
            payer=self.sender_keypair.pubkey(),
            instructions=[transfer_instruction],
            address_lookup_table_accounts=[],
            recent_blockhash=recent_blockhash
        )

        # Create and sign the transaction
        transaction = VersionedTransaction(message, [self.sender_keypair])
        
        # Extract the signature bytes for manipulation
        signature_bytes = bytes(transaction.signatures[0])
        
        return transaction, signature_bytes, str(destination), amount_lamports

    def test_malleability_scenario_A(self, original_signature: bytes) -> Tuple[bytes, str, TestResult, str]:
        """
        Test Scenario A: Standard Malleability Attack (S' = L - S)
        """
        try:
            # Extract R (first 32 bytes) and S (last 32 bytes)
            R_bytes = original_signature[:32]
            S_bytes = original_signature[32:]
            
            # Convert S from little-endian bytes to integer
            S_int = int.from_bytes(S_bytes, byteorder='little')
            
            # Calculate S' = L - S (additive inverse modulo L)
            S_prime_int = L - S_int
            
            # Convert S' back to 32-byte little-endian format
            S_prime_bytes = S_prime_int.to_bytes(32, byteorder='little')
            
            # Combine R with manipulated S'
            manipulated_signature = R_bytes + S_prime_bytes
            
            description = f"Standard malleability: S' = L - S"
            
            # Test the manipulated signature
            status, message = self._test_manipulated_signature(manipulated_signature)
            
            return manipulated_signature, description, status, message
            
        except Exception as e:
            error_msg = f"Failed to create Scenario A manipulation: {str(e)}"
            return b"", f"Scenario A construction failed: {str(e)}", TestResult.CONSTRUCTION_FAILED, error_msg

    def test_malleability_scenario_B(self, original_signature: bytes) -> Tuple[bytes, str, TestResult, str]:
        """
        Test Scenario B: Non-Canonical Signature (S'' = S + L)
        """
        try:
            # Extract R (first 32 bytes) and S (last 32 bytes)
            R_bytes = original_signature[:32]
            S_bytes = original_signature[32:]
            
            # Convert S from little-endian bytes to integer
            S_int = int.from_bytes(S_bytes, byteorder='little')
            
            # Calculate S'' = S + L (non-canonical, outside [0,L) range)
            S_double_prime_int = S_int + L
            
            # Convert S'' back to 32-byte little-endian format
            # This will overflow, creating a non-canonical signature
            S_double_prime_bytes = S_double_prime_int.to_bytes(32, byteorder='little')
            
            # Combine R with manipulated S''
            manipulated_signature = R_bytes + S_double_prime_bytes
            
            description = f"Non-canonical signature: S'' = S + L"
            
            # Test the manipulated signature
            status, message = self._test_manipulated_signature(manipulated_signature)
            
            return manipulated_signature, description, status, message
            
        except Exception as e:
            error_msg = f"Failed to create Scenario B manipulation: {str(e)}"
            return b"", f"Scenario B construction failed: {str(e)}", TestResult.CONSTRUCTION_FAILED, error_msg

    def test_malleability_scenario_C(self, original_signature: bytes) -> Tuple[bytes, str, TestResult, str]:
        """
        Test Scenario C: R Component Manipulation
        """
        try:
            # Extract R (first 32 bytes) and S (last 32 bytes)
            R_bytes = bytearray(original_signature[:32])  # Make mutable
            S_bytes = original_signature[32:]
            
            # Manipulate the last byte of R using XOR with a random value
            xor_value = random.randint(1, 255)
            original_last_byte = R_bytes[-1]
            R_bytes[-1] ^= xor_value
            
            # Convert back to bytes and combine with original S
            manipulated_R_bytes = bytes(R_bytes)
            manipulated_signature = manipulated_R_bytes + S_bytes
            
            description = f"R component manipulation: XOR last byte with 0x{xor_value:02x}"
            
            # Test the manipulated signature
            status, message = self._test_manipulated_signature(manipulated_signature)
            
            return manipulated_signature, description, status, message
            
        except Exception as e:
            error_msg = f"Failed to create Scenario C manipulation: {str(e)}"
            return b"", f"Scenario C construction failed: {str(e)}", TestResult.CONSTRUCTION_FAILED, error_msg

    def _test_manipulated_signature(self, manipulated_signature: bytes) -> Tuple[TestResult, str]:
        """
        Test a manipulated signature by attempting to create and send a transaction.
        """
        try:
            # Create a dummy transaction message for testing
            destination = Keypair().pubkey()
            transfer_instruction = transfer(
                TransferParams(
                    from_pubkey=self.sender_keypair.pubkey(),
                    to_pubkey=destination,
                    lamports=1_000_000
                )
            )
            
            recent_blockhash_response = self.rpc_client.get_latest_blockhash()
            recent_blockhash = recent_blockhash_response.value.blockhash
            
            message = MessageV0.try_compile(
                payer=self.sender_keypair.pubkey(),
                instructions=[transfer_instruction],
                address_lookup_table_accounts=[],
                recent_blockhash=recent_blockhash
            )
            
            # Create transaction with legitimate signature first
            legitimate_transaction = VersionedTransaction(message, [self.sender_keypair])
            
            # Get the serialized transaction and replace the signature
            transaction_bytes = bytearray(bytes(legitimate_transaction))
            
            # Replace signature (starts at byte 1, length 64)
            transaction_bytes[1:65] = manipulated_signature
            
            # Attempt to send the manipulated transaction
            try:
                response = self.rpc_client.send_raw_transaction(bytes(transaction_bytes))
                
                if response.value:
                    # Transaction was accepted - this is bad!
                    return TestResult.FAILED_UNEXPECTEDLY_ACCEPTED, f"Transaction accepted with signature: {response.value}"
                else:
                    # Response was None, but no exception - unclear result
                    return TestResult.ERROR, f"Unclear response: {response}"
                    
            except Exception as rpc_error:
                # Transaction was rejected - this is what we expect
                error_message = str(rpc_error).lower()
                
                # Check if the error is signature-related (expected)
                if any(keyword in error_message for keyword in [
                    'invalid signature', 'signature verification failed',
                    'invalid transaction', 'malformed', 'verification'
                ]):
                    return TestResult.REJECTED_AS_EXPECTED, f"Properly rejected: {str(rpc_error)[:100]}..."
                else:
                    return TestResult.ERROR, f"Unexpected rejection reason: {str(rpc_error)[:100]}..."
                    
        except Exception as e:
            return TestResult.CONSTRUCTION_FAILED, f"Transaction construction failed: {str(e)}"

    def run_single_iteration(self, iteration: int) -> Dict:
        """
        Execute all three malleability test scenarios for a single iteration.
        
        Args:
            iteration: Current iteration number
            
        Returns:
            Dict: Results for this iteration
        """
        try:
            # Create the original legitimate transaction for this iteration
            original_transaction, original_signature_bytes, destination, amount = self.create_original_transaction()
            original_signature_hex = original_signature_bytes.hex()
            
            # Execute all three test scenarios
            scenarios = [
                (TestScenario.SCENARIO_A, self.test_malleability_scenario_A),
                (TestScenario.SCENARIO_B, self.test_malleability_scenario_B),
                (TestScenario.SCENARIO_C, self.test_malleability_scenario_C)
            ]
            
            iteration_results = {
                'iteration': iteration,
                'original_signature': original_signature_hex,
                'destination': destination,
                'amount': amount,
                'scenarios': {},
                'success': True,
                'passed_tests': 0,
                'failed_tests': 0
            }
            
            for scenario_enum, test_function in scenarios:
                # Execute the specific scenario test
                manipulated_sig, description, status, message = test_function(original_signature_bytes)
                
                # Determine if test passed (we expect rejection)
                test_passed = status == TestResult.REJECTED_AS_EXPECTED
                
                if test_passed:
                    iteration_results['passed_tests'] += 1
                    self.scenario_stats[scenario_enum]["passed"] += 1
                else:
                    iteration_results['failed_tests'] += 1
                    iteration_results['success'] = False
                    if status == TestResult.ERROR or status == TestResult.CONSTRUCTION_FAILED:
                        self.scenario_stats[scenario_enum]["errors"] += 1
                    else:
                        self.scenario_stats[scenario_enum]["failed"] += 1
                
                # Log detailed results
                self._log_test_result(
                    iteration,
                    scenario_enum,
                    original_signature_hex,
                    manipulated_sig.hex() if manipulated_sig else "",
                    description,
                    status,
                    message,
                    test_passed,
                    destination,
                    amount
                )
                
                # Store in iteration results
                iteration_results['scenarios'][scenario_enum.value] = {
                    'status': status.value,
                    'test_passed': test_passed
                }
                
                self.total_tests_run += 1
                if test_passed:
                    self.total_passed += 1
                else:
                    self.total_failed += 1
            
            return iteration_results
            
        except Exception as e:
            logger.error(f"💥 Critical failure in iteration {iteration}: {str(e)}")
            return {
                'iteration': iteration,
                'success': False,
                'error': str(e)
            }

    def run_iterative_malleability_tests(self) -> Dict:
        """
        Execute iterative malleability tests for the specified number of iterations.
        
        Returns:
            Dict: Comprehensive test results summary
        """
        start_time = time.time()
        
        logger.info("=" * 80)
        logger.info(f"🚀 Starting Iterative Ed25519 Signature Malleability Tests")
        logger.info(f"📊 Total Iterations: {self.iterations}")
        logger.info(f"🎯 Tests per Iteration: 3 (Scenarios A, B, C)")
        logger.info(f"📈 Total Tests: {self.iterations * 3}")
        logger.info("=" * 80)
        
        all_results = []
        
        # Progress tracking
        progress_interval = max(1, self.iterations // 20)  # Show progress every 5%
        
        for iteration in range(1, self.iterations + 1):
            # Show progress
            if iteration % progress_interval == 0 or iteration == 1 or iteration == self.iterations:
                progress = (iteration / self.iterations) * 100
                logger.info(f"🔄 Progress: {iteration}/{self.iterations} iterations ({progress:.1f}%)")
            
            # Run tests for this iteration
            iteration_result = self.run_single_iteration(iteration)
            all_results.append(iteration_result)
            
            # Add small delay to avoid overwhelming the RPC endpoint
            if iteration < self.iterations:
                time.sleep(0.1)  # 100ms delay between iterations
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        # Compile final results
        final_results = {
            'iterations': self.iterations,
            'total_duration_seconds': round(total_duration, 2),
            'total_tests_run': self.total_tests_run,
            'total_passed': self.total_passed,
            'total_failed': self.total_failed,
            'success_rate': round((self.total_passed / self.total_tests_run) * 100, 2) if self.total_tests_run > 0 else 0,
            'scenario_statistics': self.scenario_stats,
            'overall_success': self.total_failed == 0,
            'csv_filename': self.csv_filename
        }
        
        # Print comprehensive final results
        self._print_final_results(final_results)
        
        return final_results

    def _print_final_results(self, results: Dict):
        """Print a comprehensive summary of all iterative test results."""
        logger.info(f"\n{'='*80}")
        logger.info("📊 COMPREHENSIVE ITERATIVE TEST RESULTS SUMMARY")
        logger.info(f"{'='*80}")
        
        logger.info(f"🔄 Total Iterations: {results['iterations']}")
        logger.info(f"⏱️  Total Duration: {results['total_duration_seconds']} seconds")
        logger.info(f"⚡ Average per Iteration: {results['total_duration_seconds'] / results['iterations']:.2f} seconds")
        logger.info(f"📈 Total Tests Executed: {results['total_tests_run']}")
        logger.info(f"✅ Tests Passed: {results['total_passed']}")
        logger.info(f"❌ Tests Failed: {results['total_failed']}")
        logger.info(f"📊 Success Rate: {results['success_rate']}%")
        
        # Print detailed scenario statistics
        logger.info(f"\n📋 SCENARIO BREAKDOWN:")
        for scenario, stats in results['scenario_statistics'].items():
            total_scenario_tests = stats['passed'] + stats['failed'] + stats['errors']
            scenario_success_rate = (stats['passed'] / total_scenario_tests) * 100 if total_scenario_tests > 0 else 0
            
            logger.info(f"  🎯 {scenario.value}:")
            logger.info(f"     ✅ Passed: {stats['passed']}")
            logger.info(f"     ❌ Failed: {stats['failed']}")
            logger.info(f"     ⚠️  Errors: {stats['errors']}")
            logger.info(f"     📈 Success Rate: {scenario_success_rate:.1f}%")
        
        # Overall conclusion
        logger.info(f"\n{'='*80}")
        if results['overall_success']:
            logger.info("🎉 OVERALL CONCLUSION: ALL TESTS PASSED!")
            logger.info("✅ Solana Devnet properly rejects ALL manipulated signatures")
            logger.info("✅ Implementation correctly follows RFC 8032 security requirements")
            logger.info("🔒 The system is resistant to tested malleability attacks")
        else:
            logger.error("🚨 OVERALL CONCLUSION: SOME TESTS FAILED!")
            logger.error("❌ Solana Devnet accepted one or more manipulated signatures")
            logger.error("⚠️  This may indicate potential security vulnerabilities")
            logger.error("🔍 Review detailed results for analysis")
        
        logger.info(f"{'='*80}")
        logger.info(f"📁 Detailed results saved to: {results['csv_filename']}")

def parse_arguments():
    """Parse command line arguments."""
    if len(sys.argv) == 1:
        return 100  # Default iterations
    
    try:
        iterations = int(sys.argv[1])
        if iterations <= 0:
            raise ValueError("Iterations must be positive")
        return iterations
    except ValueError as e:
        print(f"Error: Invalid number of iterations. {e}")
        print("Usage: python mallabelity_tester.py [iterations]")
        print("Example: python mallabelity_tester.py 1000")
        sys.exit(1)

def main():
    """Main function to run the iterative malleability tests."""
    iterations = parse_arguments()
    
    print(f"🔬 Enhanced Ed25519 Signature Malleability Tester v3.0")
    print(f"🎯 Testing Solana Devnet against signature manipulation attacks")
    print(f"🔄 Running {iterations} iterations ({iterations * 3} total tests)")
    print(f"⏱️  Estimated duration: {iterations * 0.5:.1f}-{iterations * 2:.1f} seconds\n")
    
    # Confirm if running large number of tests
    if iterations > 1000:
        response = input(f"⚠️  You're about to run {iterations} iterations ({iterations * 3} tests). Continue? (y/N): ")
        if response.lower() != 'y':
            print("Test cancelled.")
            sys.exit(0)
    
    tester = EnhancedMalleabilityTester(iterations)
    results = tester.run_iterative_malleability_tests()
    
    print(f"\n📁 Test completed. Detailed results saved to: {results['csv_filename']}")
    print(f"🎭 Overall Success: {'✅ PASSED' if results['overall_success'] else '❌ FAILED'}")
    print(f"📊 Tests Passed: {results['total_passed']}/{results['total_tests_run']} ({results['success_rate']}%)")
    print(f"⏱️  Total Duration: {results['total_duration_seconds']} seconds")
    
    return results

if __name__ == "__main__":
    main()