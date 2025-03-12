use ring::aead::{
	Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use ring::error::Unspecified;
use ring::rand::SecureRandom;

// Custom nonce sequence for AES-GCM
pub struct CounterNonceSequence {
	counter: u64,
}

impl CounterNonceSequence {
	pub fn new(counter: u64) -> Self {
		CounterNonceSequence { counter }
	}
}

impl NonceSequence for CounterNonceSequence {
	fn advance(&mut self) -> Result<Nonce, Unspecified> {
		let mut nonce_bytes = [0u8; 12]; // 96 bits
		let counter_bytes = self.counter.to_be_bytes();
		nonce_bytes[4..12].copy_from_slice(&counter_bytes);
		self.counter += 1;
		Nonce::try_assume_unique_for_key(&nonce_bytes)
	}
}

pub struct Encryptor {
	key: [u8; 32],
	secure_random: ring::rand::SystemRandom,
}

impl Encryptor {
	pub fn new(key: [u8; 32]) -> Self {
		Encryptor {
			key,
			secure_random: ring::rand::SystemRandom::new(),
		}
	}

	pub fn encrypt(&self, counter: u64, message: &[u8]) -> Result<Vec<u8>, String> {
		let unbound_key = match UnboundKey::new(&AES_256_GCM, &self.key) {
			Ok(k) => k,
			Err(_) => return Err("Failed to create encryption key".to_string()),
		};

		let mut sequence = CounterNonceSequence::new(counter);
		let mut sealing_key = SealingKey::new(unbound_key, &mut sequence);

		let mut in_out = message.to_vec();
		let aad = Aad::empty();

		match sealing_key.seal_in_place_append_tag(aad, &mut in_out) {
			Ok(_) => Ok(in_out),
			Err(_) => Err("Encryption failed".to_string()),
		}
	}

	pub fn decrypt(&self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
		if ciphertext.len() < AES_256_GCM.tag_len() {
			return Err("Ciphertext too short".to_string());
		}

		let unbound_key = match UnboundKey::new(&AES_256_GCM, &self.key) {
			Ok(k) => k,
			Err(_) => return Err("Failed to create decryption key".to_string()),
		};

		let mut sequence = CounterNonceSequence::new(counter);
		let mut opening_key = OpeningKey::new(unbound_key, &mut sequence);

		let mut in_out = ciphertext.to_vec();
		let aad = Aad::empty();

		match opening_key.open_in_place(aad, &mut in_out) {
			Ok(plaintext) => Ok(plaintext.to_vec()),
			Err(_) => Err("Decryption failed".to_string()),
		}
	}

	pub fn generate_random_key() -> Result<[u8; 32], String> {
		let mut key = [0u8; 32];
		let rng = ring::rand::SystemRandom::new();

		match rng.fill(&mut key) {
			Ok(_) => Ok(key),
			Err(_) => Err("Failed to generate random key".to_string()),
		}
	}
}
