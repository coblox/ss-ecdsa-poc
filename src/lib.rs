#![allow(non_snake_case)]
pub mod alice;
pub mod bob;
pub mod commited_nizk;
pub mod ecdsa;
pub mod messages;
pub mod nizk_sigma;

use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use merlin::{Transcript, TranscriptRng};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

#[derive(Debug, Clone, Copy)]
pub struct KeyPair {
    pub secret_key: FE,
    pub public_key: GE,
}

impl From<KeyPair> for party_one::EcKeyPair {
    fn from(keypair: KeyPair) -> Self {
        party_one::EcKeyPair {
            secret_share: keypair.secret_key,
            public_share: keypair.public_key,
        }
    }
}

impl From<KeyPair> for party_two::EcKeyPair {
    fn from(keypair: KeyPair) -> Self {
        Self {
            secret_share: keypair.secret_key,
            public_share: keypair.public_key,
        }
    }
}

impl From<KeyPair> for party_two::EphEcKeyPair {
    fn from(keypair: KeyPair) -> Self {
        Self {
            secret_share: keypair.secret_key,
            public_share: keypair.public_key,
        }
    }
}

impl From<FE> for KeyPair {
    fn from(secret_key: FE) -> KeyPair {
        let public_key = GE::generator() * secret_key;
        KeyPair {
            secret_key,
            public_key,
        }
    }
}

impl KeyPair {
    fn new_random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> KeyPair {
        let mut x = [0u8; 32];
        rng.fill_bytes(&mut x);
        let fe: FE = ECScalar::from(&BigInt::from(&x[..]));
        KeyPair::from(fe)
    }
}

pub trait SSEcdsaTranscript {
    fn add_point(&mut self, label: &'static [u8], point: GE);
    fn rng(&self) -> TranscriptRng;
    fn state_id(&self) -> String;
}

impl SSEcdsaTranscript for Transcript {
    fn add_point(&mut self, label: &'static [u8], point: GE) {
        self.append_message(label, &point.get_element().serialize()[..]);
    }

    fn rng(&self) -> TranscriptRng {
        self.build_rng().finalize(&mut rand::thread_rng())
    }

    fn state_id(&self) -> String {
        let mut transcript = self.clone();
        let mut debug = [0u8; 8];
        transcript.challenge_bytes(b"debug", &mut debug[..]);
        hex::encode(&debug[..])
    }
}
