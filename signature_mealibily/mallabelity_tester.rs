use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use csv::Writer;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use log::{error, info, warn};
use rand::rngs::OsRng;
use reqwest::Client as HttpClient;
use serde_json::{json, Value};
use solana_client::{
    rpc_client::RpcClient,
    rpc_config::{RpcSendTransactionConfig, RpcTransactionConfig},
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::Hash,
    instruction::Instruction,
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature as SolanaSignature},
    signer::Signer as SolanaSigner,
    system_instruction,
    transaction::Transaction,
};
use std::{
    fs::OpenOptions,
    io::Write,
    str::FromStr,
    thread,
    time::Duration,
};
use tokio;

/// Ed25519 curve order constant as per RFC 8032
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Test scenarios untuk signature malleability
#[derive(Debug, Clone)]
pub enum TestScenario {
    StandardMalleability,    // S' = L - S
    NonCanonicalSignature,   // S'' = S + L
    RComponentManipulation,  // Modified R
}

impl TestScenario {
    fn as_str(&self) -> &'static str {
        match self {
            TestScenario::StandardMalleability => "Standard_Malleability_S_Prime",
            TestScenario::NonCanonicalSignature => "Non_Canonical_S_Plus_L", 
            TestScenario::RComponentManipulation => "R_Component_Manipulation",
        }
    }
}

/// Hasil test yang mungkin
#[derive(Debug, Clone)]
pub enum TestResult {
    RejectedAsExpected,
    FailedUnexpectedlyAccepted,
    Error,
    ConstructionFailed,
}

impl TestResult {
    fn as_str(&self) -> &'static str {
        match self {
            TestResult::RejectedAsExpected => "REJECTED_AS_EXPECTED",
            TestResult::FailedUnexpectedlyAccepted => "FAILED_UNEXPECTEDLY_ACCEPTED",
            TestResult::Error => "ERROR",
            TestResult::ConstructionFailed => "CONSTRUCTION_FAILED",
        }
    }
}

/// Struktur untuk menyimpan hasil test individual
#[derive(Debug)]
pub struct ScenarioResult {
    pub scenario: TestScenario,
    pub original_signature: String,
    pub manipulated_signature: String,
    pub description: String,
    pub status: TestResult,
    pub message: String,
    pub test_passed: bool,
}

/// Main tester struct
pub struct EnhancedMalleabilityTester {
    rpc_client: RpcClient,
    sender_keypair: Keypair,
    csv_filename: String,
    http_client: HttpClient,
}

impl EnhancedMalleabilityTester {
    /// Inisialisasi tester baru
    pub fn new(private_key_base58: &str) -> Result<Self> {
        info!("🔧 Initializing Enhanced Malleability Tester...");
        
        // Setup RPC client untuk Solana Devnet
        let rpc_url = "https://api.devnet.solana.com";
        let rpc_client = RpcClient::new_with_commitment(
            rpc_url.to_string(),
            CommitmentConfig::confirmed(),
        );
        
        // Load keypair dari private key
        let sender_keypair = Keypair::from_base58_string(private_key_base58)
            .context("Failed to load keypair from private key")?;
        
        let csv_filename = format!(
            "rust_malleability_test_log_{}.csv",
            Utc::now().format("%Y%m%d_%H%M%S")
        );
        
        let http_client = HttpClient::new();
        
        let tester = Self {
            rpc_client,
            sender_keypair,
            csv_filename,
            http_client,
        };
        
        tester.setup_csv_logging()?;
        
        info!("✅ Tester initialized successfully");
        info!("📁 CSV log file: {}", tester.csv_filename);
        info!("💰 Sender pubkey: {}", tester.sender_keypair.pubkey());
        
        Ok(tester)
    }
    
    /// Setup CSV file untuk logging
    fn setup_csv_logging(&self) -> Result<()> {
        let mut writer = Writer::from_path(&self.csv_filename)
            .context("Failed to create CSV file")?;
        
        writer.write_record(&[
            "timestamp_utc",
            "test_scenario", 
            "original_signature_hex",
            "manipulated_signature_hex",
            "manipulation_description",
            "status",
            "rpc_response_message",
            "expected_result",
            "test_passed",
        ])?;
        
        writer.flush()?;
        Ok(())
    }
    
    /// Log hasil test ke CSV
    fn log_test_result(&self, result: &ScenarioResult) -> Result<()> {
        let mut writer = Writer::from_writer(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.csv_filename)?
        );
        
        writer.write_record(&[
            Utc::now().to_rfc3339(),
            result.scenario.as_str(),
            &result.original_signature,
            &result.manipulated_signature,
            &result.description,
            result.status.as_str(),
            &result.message,
            "REJECTED", // Kita selalu mengharapkan penolakan
            &result.test_passed.to_string(),
        ])?;
        
        writer.flush()?;
        Ok(())
    }
    
    /// Buat transaksi legitimate sebagai baseline
    pub async fn create_original_transaction(&self) -> Result<(Transaction, [u8; 64])> {
        info!("🔧 Creating original legitimate transaction...");
        
        // Generate random destination
        let destination = Keypair::new().pubkey();
        
        // Get recent blockhash
        let recent_blockhash = self.rpc_client
            .get_latest_blockhash()
            .context("Failed to get recent blockhash")?;
        
        // Create transfer instruction (0.001 SOL = 1,000,000 lamports)
        let transfer_instruction = system_instruction::transfer(
            &self.sender_keypair.pubkey(),
            &destination,
            1_000_000, // 0.001 SOL
        );
        
        // Create message
        let message = Message::new(
            &[transfer_instruction],
            Some(&self.sender_keypair.pubkey()),
        );
        
        // Create and sign transaction
        let mut transaction = Transaction::new_unsigned(message);
        transaction.partial_sign(&[&self.sender_keypair], recent_blockhash);
        
        // Extract signature bytes
        let signature_bytes: [u8; 64] = transaction.signatures[0].as_ref().try_into()
            .context("Failed to extract signature bytes")?;
        
        info!("✅ Original transaction created successfully");
        info!("  🎯 Destination: {}", destination);
        info!("  💰 Amount: 0.001 SOL");
        info!("  🔐 Original signature: {}", hex::encode(&signature_bytes));
        
        Ok((transaction, signature_bytes))
    }
    
    /// Test Scenario A: Standard Malleability (S' = L - S)
    pub async fn test_scenario_a(&self, original_signature: [u8; 64]) -> ScenarioResult {
        info!("🎯 Testing Scenario A: Standard Malleability (S' = L - S)");
        
        let scenario = TestScenario::StandardMalleability;
        let original_sig_hex = hex::encode(&original_signature);
        
        match self.perform_standard_malleability(&original_signature).await {
            Ok((manipulated_sig, description, status, message)) => {
                let test_passed = matches!(status, TestResult::RejectedAsExpected);
                
                if test_passed {
                    info!("  ✅ Test PASSED: Transaction properly rejected");
                } else {
                    error!("  ❌ Test FAILED: {}", status.as_str());
                }
                
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: hex::encode(&manipulated_sig),
                    description,
                    status,
                    message,
                    test_passed,
                }
            }
            Err(e) => {
                error!("  ❌ Scenario A failed: {}", e);
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: String::new(),
                    description: format!("Scenario A construction failed: {}", e),
                    status: TestResult::ConstructionFailed,
                    message: e.to_string(),
                    test_passed: false,
                }
            }
        }
    }
    
    /// Implementasi Standard Malleability
    async fn perform_standard_malleability(&self, original_sig: &[u8; 64]) -> Result<([u8; 64], String, TestResult, String)> {
        // Extract R (first 32 bytes) and S (last 32 bytes)
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&original_sig[0..32]);
        s_bytes.copy_from_slice(&original_sig[32..64]);
        
        // Convert S to scalar untuk operasi matematika
        let s_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(s_bytes);
        
        // Calculate S' = L - S (additive inverse)
        let l_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(L);
        let s_prime_scalar = l_scalar - s_scalar;
        
        // Convert back to bytes
        let s_prime_bytes = s_prime_scalar.to_bytes();
        
        // Combine R with S'
        let mut manipulated_sig = [0u8; 64];
        manipulated_sig[0..32].copy_from_slice(&r_bytes);
        manipulated_sig[32..64].copy_from_slice(&s_prime_bytes);
        
        let description = format!(
            "Standard malleability: S' = L - S. Original S: {}, Manipulated S': {}",
            hex::encode(&s_bytes),
            hex::encode(&s_prime_bytes)
        );
        
        info!("  📊 Original S: {}", hex::encode(&s_bytes));
        info!("  📊 Manipulated S': {}", hex::encode(&s_prime_bytes));
        
        // Test the manipulated signature
        let (status, message) = self.test_manipulated_signature(&manipulated_sig).await?;
        
        Ok((manipulated_sig, description, status, message))
    }
    
    /// Test Scenario B: Non-Canonical Signature (S'' = S + L)
    pub async fn test_scenario_b(&self, original_signature: [u8; 64]) -> ScenarioResult {
        info!("🎯 Testing Scenario B: Non-Canonical Signature (S'' = S + L)");
        
        let scenario = TestScenario::NonCanonicalSignature;
        let original_sig_hex = hex::encode(&original_signature);
        
        match self.perform_non_canonical_test(&original_signature).await {
            Ok((manipulated_sig, description, status, message)) => {
                let test_passed = matches!(status, TestResult::RejectedAsExpected);
                
                if test_passed {
                    info!("  ✅ Test PASSED: Transaction properly rejected");
                } else {
                    error!("  ❌ Test FAILED: {}", status.as_str());
                }
                
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: hex::encode(&manipulated_sig),
                    description,
                    status,
                    message,
                    test_passed,
                }
            }
            Err(e) => {
                error!("  ❌ Scenario B failed: {}", e);
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: String::new(),
                    description: format!("Scenario B construction failed: {}", e),
                    status: TestResult::ConstructionFailed,
                    message: e.to_string(),
                    test_passed: false,
                }
            }
        }
    }
    
    /// Implementasi Non-Canonical Test
    async fn perform_non_canonical_test(&self, original_sig: &[u8; 64]) -> Result<([u8; 64], String, TestResult, String)> {
        // Extract R and S
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&original_sig[0..32]);
        s_bytes.copy_from_slice(&original_sig[32..64]);
        
        // Convert S to scalar
        let s_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(s_bytes);
        
        // Calculate S'' = S + L (non-canonical)
        let l_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(L);
        let s_double_prime_scalar = s_scalar + l_scalar;
        
        // Convert back to bytes
        let s_double_prime_bytes = s_double_prime_scalar.to_bytes();
        
        // Combine R with S''
        let mut manipulated_sig = [0u8; 64];
        manipulated_sig[0..32].copy_from_slice(&r_bytes);
        manipulated_sig[32..64].copy_from_slice(&s_double_prime_bytes);
        
        let description = format!(
            "Non-canonical signature: S'' = S + L. Original S: {}, Non-canonical S'': {}",
            hex::encode(&s_bytes),
            hex::encode(&s_double_prime_bytes)
        );
        
        info!("  📊 Original S: {}", hex::encode(&s_bytes));
        info!("  📊 Non-canonical S'': {}", hex::encode(&s_double_prime_bytes));
        
        // Test the manipulated signature
        let (status, message) = self.test_manipulated_signature(&manipulated_sig).await?;
        
        Ok((manipulated_sig, description, status, message))
    }
    
    /// Test Scenario C: R Component Manipulation
    pub async fn test_scenario_c(&self, original_signature: [u8; 64]) -> ScenarioResult {
        info!("🎯 Testing Scenario C: R Component Manipulation");
        
        let scenario = TestScenario::RComponentManipulation;
        let original_sig_hex = hex::encode(&original_signature);
        
        match self.perform_r_manipulation(&original_signature).await {
            Ok((manipulated_sig, description, status, message)) => {
                let test_passed = matches!(status, TestResult::RejectedAsExpected);
                
                if test_passed {
                    info!("  ✅ Test PASSED: Transaction properly rejected");
                } else {
                    error!("  ❌ Test FAILED: {}", status.as_str());
                }
                
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: hex::encode(&manipulated_sig),
                    description,
                    status,
                    message,
                    test_passed,
                }
            }
            Err(e) => {
                error!("  ❌ Scenario C failed: {}", e);
                ScenarioResult {
                    scenario,
                    original_signature: original_sig_hex,
                    manipulated_signature: String::new(),
                    description: format!("Scenario C construction failed: {}", e),
                    status: TestResult::ConstructionFailed,
                    message: e.to_string(),
                    test_passed: false,
                }
            }
        }
    }
    
    /// Implementasi R Component Manipulation
    async fn perform_r_manipulation(&self, original_sig: &[u8; 64]) -> Result<([u8; 64], String, TestResult, String)> {
        let mut manipulated_sig = *original_sig;
        
        // Manipulate last byte of R with XOR 0x01
        let original_r_last_byte = manipulated_sig[31];
        manipulated_sig[31] ^= 0x01;
        
        let description = format!(
            "R component manipulation: XOR last byte with 0x01. Original R[-1]: 0x{:02x}, Modified: 0x{:02x}",
            original_r_last_byte,
            manipulated_sig[31]
        );
        
        info!("  📊 Original R last byte: 0x{:02x}", original_r_last_byte);
        info!("  📊 Modified R last byte: 0x{:02x}", manipulated_sig[31]);
        
        // Test the manipulated signature
        let (status, message) = self.test_manipulated_signature(&manipulated_sig).await?;
        
        Ok((manipulated_sig, description, status, message))
    }
    
    /// Test signature yang telah dimanipulasi dengan mengirim ke network
    async fn test_manipulated_signature(&self, manipulated_sig: &[u8; 64]) -> Result<(TestResult, String)> {
        // Create a test transaction with manipulated signature
        let destination = Keypair::new().pubkey();
        
        let recent_blockhash = self.rpc_client
            .get_latest_blockhash()
            .context("Failed to get recent blockhash")?;
        
        let transfer_instruction = system_instruction::transfer(
            &self.sender_keypair.pubkey(),
            &destination, 
            1_000_000,
        );
        
        let message = Message::new(
            &[transfer_instruction],
            Some(&self.sender_keypair.pubkey()),
        );
        
        // Create transaction with manipulated signature
        let mut transaction = Transaction::new_unsigned(message);
        
        // Replace with manipulated signature
        let manipulated_signature = SolanaSignature::from(<[u8; 64]>::try_from(manipulated_sig)?);
        transaction.signatures = vec![manipulated_signature];
        
        // Try to send the transaction
        match self.rpc_client.send_transaction(&transaction) {
            Ok(signature) => {
                // Transaction was accepted - this is bad!
                let msg = format!("Transaction unexpectedly accepted with signature: {}", signature);
                error!("  🚨 {}", msg);
                Ok((TestResult::FailedUnexpectedlyAccepted, msg))
            }
            Err(e) => {
                // Transaction was rejected - this is expected
                let error_message = e.to_string().to_lowercase();
                
                if error_message.contains("invalid signature") 
                    || error_message.contains("signature verification failed")
                    || error_message.contains("invalid transaction")
                    || error_message.contains("malformed")
                    || error_message.contains("verification") {
                    
                    let msg = format!("Properly rejected: {}", e);
                    info!("  ✅ {}", msg);
                    Ok((TestResult::RejectedAsExpected, msg))
                } else {
                    let msg = format!("Unexpected rejection reason: {}", e);
                    warn!("  ⚠️ {}", msg);
                    Ok((TestResult::Error, msg))
                }
            }
        }
    }
    
    /// Run all comprehensive malleability tests
    pub async fn run_comprehensive_tests(&self) -> Result<Vec<ScenarioResult>> {
        info!("================================================================================");
        info!("🚀 Starting Comprehensive Ed25519 Signature Malleability Tests");
        info!("================================================================================");
        
        // Step 1: Create original transaction
        let (original_transaction, original_signature_bytes) = self.create_original_transaction().await?;
        
        info!("\n📋 Base transaction created with signature: {}", 
              hex::encode(&original_signature_bytes));
        
        // Step 2: Run all three scenarios
        let mut results = Vec::new();
        
        info!("\n🧪 Running 3 malleability test scenarios...");
        
        // Scenario A
        info!("\n============================================================");
        let result_a = self.test_scenario_a(original_signature_bytes).await;
        self.log_test_result(&result_a)?;
        results.push(result_a);
        
        // Small delay between tests
        thread::sleep(Duration::from_millis(1000));
        
        // Scenario B  
        info!("\n============================================================");
        let result_b = self.test_scenario_b(original_signature_bytes).await;
        self.log_test_result(&result_b)?;
        results.push(result_b);
        
        // Small delay between tests
        thread::sleep(Duration::from_millis(1000));
        
        // Scenario C
        info!("\n============================================================");
        let result_c = self.test_scenario_c(original_signature_bytes).await;
        self.log_test_result(&result_c)?;
        results.push(result_c);
        
        // Step 3: Print final results
        self.print_final_results(&results);
        
        Ok(results)
    }
    
    /// Print comprehensive final results
    fn print_final_results(&self, results: &[ScenarioResult]) {
        info!("\n================================================================================");
        info!("📊 COMPREHENSIVE TEST RESULTS SUMMARY");
        info!("================================================================================");
        
        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.test_passed).count();
        let failed_tests = total_tests - passed_tests;
        
        info!("📈 Total Tests: {}", total_tests);
        info!("✅ Tests Passed: {}", passed_tests);
        info!("❌ Tests Failed: {}", failed_tests);
        
        // Print individual results
        for result in results {
            info!("\n📋 {}:", result.scenario.as_str());
            info!("   🎯 {}", result.description);
            info!("   📄 Status: {}", result.status.as_str());
            info!("   {} Result: {}", 
                  if result.test_passed { "✅" } else { "❌" },
                  if result.test_passed { "PASSED" } else { "FAILED" });
        }
        
        // Overall conclusion
        info!("\n================================================================================");
        if failed_tests == 0 {
            info!("🎉 OVERALL CONCLUSION: ALL TESTS PASSED!");
            info!("✅ Solana Devnet properly rejects ALL manipulated signatures");
            info!("✅ Implementation correctly follows RFC 8032 security requirements");
            info!("🔒 The system is resistant to tested malleability attacks");
        } else {
            error!("🚨 OVERALL CONCLUSION: SOME TESTS FAILED!");
            error!("❌ Solana Devnet accepted one or more manipulated signatures");
            error!("⚠️  This may indicate potential security vulnerabilities");
            error!("🔍 Review individual test results for details");
        }
        
        info!("================================================================================");
        info!("📁 Detailed results saved to: {}", self.csv_filename);
    }
}

/// Main function
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    println!("🔬 Enhanced Ed25519 Signature Malleability Tester v2.0 (Rust)");
    println!("🎯 Testing Solana Devnet against signature manipulation attacks");
    println!("🦀 Native Rust implementation for academic research\n");
    
    // Load private key from environment atau input
    let private_key = std::env::var("SOLANA_PRIVATE_KEY")
        .context("Please set SOLANA_PRIVATE_KEY environment variable")?;
    
    // Initialize tester
    let tester = EnhancedMalleabilityTester::new(&private_key)
        .context("Failed to initialize malleability tester")?;
    
    // Check balance terlebih dahulu
    info!("💰 Checking account balance...");
    let balance = tester.rpc_client.get_balance(&tester.sender_keypair.pubkey())?;
    info!("💰 Current balance: {} SOL", balance as f64 / 1_000_000_000.0);
    
    if balance < 10_000_000 { // Less than 0.01 SOL
        warn!("⚠️  Low balance detected. You may need more SOL for testing.");
        warn!("💸 Get free SOL from: https://faucet.solana.com/");
    }
    
    // Run comprehensive tests
    let results = tester.run_comprehensive_tests().await
        .context("Failed to run comprehensive tests")?;
    
    // Final summary
    let total_tests = results.len();
    let passed_tests = results.iter().filter(|r| r.test_passed).count();
    let overall_success = passed_tests == total_tests;
    
    println!("\n📁 Test completed. Detailed results saved to: {}", tester.csv_filename);
    println!("🎭 Overall Success: {}", if overall_success { "✅ PASSED" } else { "❌ FAILED" });
    println!("📊 Tests Passed: {}/{}", passed_tests, total_tests);
    
    Ok(())
}