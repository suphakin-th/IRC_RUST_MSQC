use std::time::Instant;

// Session information
pub struct Session {
	pub id: String,
	pub user_id: String,
	pub started_at: Instant,
	pub last_activity: Instant,
	pub encryption_key: [u8; 32], // AES-256 key
	pub nonce_counter: u64,
}

impl Session {
	pub fn new(id: String, user_id: String, encryption_key: [u8; 32]) -> Self {
		let now = Instant::now();
		Session {
			id,
			user_id,
			started_at: now,
			last_activity: now,
			encryption_key,
			nonce_counter: 0,
		}
	}

	pub fn update_activity(&mut self) {
		self.last_activity = Instant::now();
	}

	pub fn is_expired(&self, timeout_duration: std::time::Duration) -> bool {
		Instant::now().duration_since(self.last_activity) > timeout_duration
	}

	pub fn increment_nonce(&mut self) -> u64 {
		self.nonce_counter += 1;
		self.nonce_counter
	}

	pub fn duration(&self) -> std::time::Duration {
		Instant::now().duration_since(self.started_at)
	}

	pub fn idle_time(&self) -> std::time::Duration {
		Instant::now().duration_since(self.last_activity)
	}
}
