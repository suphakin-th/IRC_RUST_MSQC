// Export client modules
pub mod client;
pub mod monitor;

// Re-export main types
pub use client::IRCClient;
pub use monitor::SessionMonitor;
