use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use secp256k1::{Message, Secp256k1};

pub fn verify(message: &Message, rx: &BigInt, s: &FE, X: &GE) -> bool {
    let secp = Secp256k1::verification_only();
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&BigInt::to_vec(&rx)[..]);
    signature[32..64].copy_from_slice(&s.get_element()[..]);
    let signature = secp256k1::Signature::from_compact(&signature[..]).unwrap();
    let public_key = X.get_element();
    match secp.verify(&message, &signature, &public_key) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn normalize_and_verify(msg: &Message, X: &GE, s: &FE, R: &GE) -> Result<Signature, ()> {
    let mut s = s.to_big_int();
    let neg_s = FE::q() - s.clone();
    if s > neg_s {
        s = neg_s;
    }
    let s = ECScalar::from(&s);
    let Rx = R.x_coor().unwrap();

    if !verify(&msg, &Rx, &s, &X) {
        return Err(());
    }

    let signature = Signature { Rx, s };

    Ok(signature)
}

pub struct Signature {
    pub Rx: BigInt,
    pub s: FE,
}
