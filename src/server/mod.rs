// Export server modules
pub mod crypto;
pub mod facade;
pub mod handler;
pub mod models;
pub mod session;

// Re-export main types
pub use facade::IRCServerFacade;
pub use models::{Channel, ChatMessage, Message, MessageType, User};
pub use session::Session;
