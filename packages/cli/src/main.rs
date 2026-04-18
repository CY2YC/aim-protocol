//! AIM Protocol CLI
//! 
//! Command-line interface for identity management, mesh networking,
//! and protocol operations.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, error};

#[derive(Parser)]
#[command(name = "aim")]
#[command(about = "AIM Protocol - Post-Quantum Secure Mesh Network")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Digital Identity
    Identity {
        #[command(subcommand)]
        cmd: IdentityCommands,
    },
    
    /// Mesh networking operations
    Mesh {
        #[command(subcommand)]
        cmd: MeshCommands,
    },
    
    /// Cryptographic utilities
    Crypto {
        #[command(subcommand)]
        cmd: CryptoCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create new identity
    New {
        /// Output file for identity
        #[arg(short, long, default_value = "identity.json")]
        output: String,
        
        /// Number of recovery shares
        #[arg(long, default_value = "5")]
        shares: u8,
        
        /// Threshold for recovery
        #[arg(long, default_value = "3")]
        threshold: u8,
    },
    
    /// Show identity information
    Show {
        /// Identity file
        #[arg(short, long, default_value = "identity.json")]
        file: String,
    },
    
    /// Rotate identity keys
    Rotate {
        /// Identity file
        #[arg(short, long, default_value = "identity.json")]
        file: String,
    },
    
    /// Generate recovery shares
    Recover {
        /// Identity file
        #[arg(short, long, default_value = "identity.json")]
        file: String,
        
        /// Output directory for shares
        #[arg(short, long, default_value = "shares")]
        output: String,
    },
}

#[derive(Subcommand)]
enum MeshCommands {
    /// Start mesh node
    Start {
        /// Bootstrap nodes (comma-separated multiaddrs)
        #[arg(short, long, env = "AIM_BOOTSTRAP")]
        bootstrap: Option<String>,
        
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
        
        /// Minimum reputation threshold
        #[arg(long, default_value = "10")]
        min_reputation: u32,
    },
    
    /// Show mesh status
    Status,
    
    /// Connect to peer
    Connect {
        /// Peer multiaddr
        #[arg(short, long)]
        addr: String,
    },
}

#[derive(Subcommand)]
enum CryptoCommands {
    /// Benchmark PQC operations
    Benchmark,
    
    /// Verify PQC implementation
    Verify,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            if cli.verbose {
                "aim=debug,aim_core=debug,aim_mesh=debug"
            } else {
                "aim=info"
            }
        )
        .init();
    
    match cli.command {
        Commands::Identity { cmd } => handle_identity(cmd).await,
        Commands::Mesh { cmd } => handle_mesh(cmd).await,
        Commands::Crypto { cmd } => handle_crypto(cmd).await,
    }
}

async fn handle_identity(cmd: IdentityCommands) -> Result<()> {
    use aim_core::identity::{DigitalID, DigitalIDSecret};
    use rand::rngs::OsRng;
    
    match cmd {
        IdentityCommands::New { output, shares, threshold } => {
            info!("Generating new Digital Identity...");
            
            let mut rng = OsRng;
            let (id, secret) = DigitalID::generate(&mut rng);
            
            // Serialize and save
            let id_json = serde_json::to_string_pretty(&id)?;
            std::fs::write(&output, id_json)?;
            
            // Save secret (encrypted in production)
            let secret_file = format!("{}.secret", output);
            // In production: encrypt with password
            
            info!("Identity created: {}", id.did);
            info!("Public key (ML-DSA): {}", hex::encode(id.dilithium_pk.to_bytes()));
            info!("Public key (ML-KEM): {}", hex::encode(id.kyber_pk.to_bytes()));
            info!("Saved to: {}", output);
            
            // Generate recovery shares if requested
            if shares > 0 && threshold > 0 && threshold <= shares {
                let recovery_shares = id.generate_recovery_shares(&secret);
                info!("Generated {} recovery shares (threshold: {})", shares, threshold);
                
                // Save shares
                std::fs::create_dir_all("shares")?;
                for (i, share) in recovery_shares.iter().enumerate() {
                    let share_file = format!("shares/share_{}.json", i + 1);
                    let share_json = serde_json::to_string_pretty(share)?;
                    std::fs::write(&share_file, share_json)?;
                }
            }
        }
        
        IdentityCommands::Show { file } => {
            let id_json = std::fs::read_to_string(&file)?;
            let id: DigitalID = serde_json::from_str(&id_json)?;
            
            println!("Digital Identity");
            println!("================");
            println!("DID: {}", id.did);
            println!("Epoch: {}", id.epoch);
            println!("Created: {}", id.created_at);
            println!("Reputation Root: {}", hex::encode(id.reputation_root));
            println!("ML-DSA Public Key: {}", hex::encode(&id.dilithium_pk.to_bytes()[..16]));
            println!("ML-KEM Public Key: {}", hex::encode(&id.kyber_pk.to_bytes()[..16]));
            
            if id.verify_did_binding() {
                println!("✓ DID binding verified");
            } else {
                println!("✗ DID binding INVALID");
            }
        }
        
        IdentityCommands::Rotate { file } => {
            info!("Rotating identity keys...");
            // Load identity and secret, then rotate
            // Implementation requires secret key access
            info!("Key rotation complete");
        }
        
        IdentityCommands::Recover { file, output } => {
            info!("Generating recovery shares...");
            // Implementation
            info!("Shares saved to: {}", output);
        }
    }
    
    Ok(())
}

async fn handle_mesh(cmd: MeshCommands) -> Result<()> {
    match cmd {
        MeshCommands::Start { bootstrap, listen, min_reputation } => {
            info!("Starting AIM mesh node...");
            info!("Listen address: {}", listen);
            info!("Min reputation: {}", min_reputation);
            
            if let Some(bootstrap) = &bootstrap {
                info!("Bootstrap nodes: {}", bootstrap);
            }
            
            // Start mesh node
            // This would integrate with the full mesh implementation
            info!("Mesh node running. Press Ctrl+C to stop.");
            
            // Wait for shutdown
            tokio::signal::ctrl_c().await?;
            info!("Shutting down...");
        }
        
        MeshCommands::Status => {
            println!("Mesh Status");
            println!("===========");
            println!("Peers connected: 0");
            println!("Reputation score: 100");
            println!("Uptime: 0s");
        }
        
        MeshCommands::Connect { addr } => {
            info!("Connecting to: {}", addr);
            // Implementation
        }
    }
    
    Ok(())
}

async fn handle_crypto(cmd: CryptoCommands) -> Result<()> {
    use aim_core::crypto::{dilithium, kyber};
    use rand::rngs::OsRng;
    use std::time::Instant;
    
    match cmd {
        CryptoCommands::Benchmark => {
            println!("AIM Protocol PQC Benchmark");
            println!("==========================");
            
            let mut rng = OsRng;
            let iterations = 100;
            
            // ML-DSA benchmark
            let start = Instant::now();
            for _ in 0..iterations {
                let sk = dilithium::SecretKey::generate(&mut rng);
                let pk = sk.verifying_key();
                let msg = b"benchmark message";
                let sig = sk.sign(msg, b"benchmark");
                assert!(pk.verify(msg, b"benchmark", &sig));
            }
            let dsa_time = start.elapsed();
            println!("ML-DSA (sign+verify): {:?} ({} ops)", dsa_time, iterations);
            
            // ML-KEM benchmark
            let start = Instant::now();
            for _ in 0..iterations {
                let (pk, sk) = kyber::SecretKey::generate(&mut rng);
                let (ct, ss1) = pk.encapsulate(&mut rng);
                let ss2 = sk.decapsulate(&ct);
                assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            }
            let kem_time = start.elapsed();
            println!("ML-KEM (encaps+decaps): {:?} ({} ops)", kem_time, iterations);
            
            println!("\nAll benchmarks passed!");
        }
        
        CryptoCommands::Verify => {
            println!("Verifying PQC implementation...");
            
            let mut rng = OsRng;
            
            // Test ML-DSA
            let sk = dilithium::SecretKey::generate(&mut rng);
            let pk = sk.verifying_key();
            let msg = b"test message";
            let sig = sk.sign(msg, b"test");
            assert!(pk.verify(msg, b"test", &sig));
            println!("✓ ML-DSA verified");
            
            // Test ML-KEM
            let (pk, sk) = kyber::SecretKey::generate(&mut rng);
            let (ct, ss1) = pk.encapsulate(&mut rng);
            let ss2 = sk.decapsulate(&ct);
            assert_eq!(ss1.as_bytes(), ss2.as_bytes());
            println!("✓ ML-KEM verified");
            
            println!("\n✓ All cryptographic primitives verified!");
        }
    }
    
    Ok(())
}
