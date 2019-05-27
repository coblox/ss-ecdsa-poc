use curv::{arithmetic::traits::Converter, elliptic::curves::traits::ECPoint, BigInt, GE};
use secp256k1::{Message, Secp256k1, Signature};

pub fn verify(message: &BigInt, rx: &BigInt, s: &BigInt, public_key: &GE) -> bool {
    let secp = Secp256k1::verification_only();
    let message = Message::from_slice(&BigInt::to_vec(&message)[..]).unwrap();
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&BigInt::to_vec(&rx)[..]);
    signature[32..64].copy_from_slice(&BigInt::to_vec(&s)[..]);
    let signature = Signature::from_compact(&signature[..]).unwrap();
    let public_key = public_key.get_element();
    match secp.verify(&message, &signature, &public_key) {
        Ok(_) => true,
        Err(_) => false,
    }
}
