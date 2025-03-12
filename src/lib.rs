// Export modules
pub mod client;
pub mod server;
pub mod utils;

// Re-export main types
pub use client::client::IRCClient;
pub use server::facade::IRCServerFacade;
pub use utils::token::TokenGenerator;
