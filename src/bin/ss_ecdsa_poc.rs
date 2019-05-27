#![allow(non_snake_case)]
use bitcoin_hashes::{self, Hash};
use curv::{elliptic::curves::traits::ECScalar, BigInt, FE};
use ss_ecdsa_poc::{alice::Alice1, bob::Bob1};

pub fn main() -> Result<(), ()> {
    // This is the message that Alice wants a signature on
    let message = bitcoin_hashes::sha256d::Hash::hash(b"Bob pays Alice 10 BTC");
    let message: FE = ECScalar::from(&BigInt::from(&message[..]));
    {
        // KEY GENERATION
        // Y is the public key Bob wants to know the private key for
        let (alice, Y) = Alice1::new(message.clone());
        println!("Alice choses a lock pre-image {:?}", alice.y.secret_key,);
        println!("[ALICE => BOB] the lock {:?}", Y);
        let (bob, kegen_msg_1) = Bob1::new(Y, message);
        println!("[BOB => ALICE] His public key Comm(X₁, nizk(X₁))");
        let (alice, keygen_msg_2) = alice.receive_message(kegen_msg_1);
        println!("[ALICE => BOB] X₂, nizk(X₂)");
        let (bob, keygen_msg_3) = bob.receive_message(keygen_msg_2)?;
        println!("[BOB => ALICE] Opens his commitment, sends c = PaillierEncrypt(x₁), N  and proofs for N");
        let (alice, keygen_msg_4) = alice.receive_message(keygen_msg_3)?;
        println!("[ALICE => BOB] PDL challenge c′");
        let (bob, keygen_msg_5) = bob.receive_message(keygen_msg_4)?;
        println!("[BOB => ALICE] Comm(Q̂)");
        let (alice, keygen_msg_6) = alice.receive_message(keygen_msg_5);
        println!("[ALICE => BOB] Reveal a,b used to produce c′");
        let (bob, keygen_msg_7) = bob.receive_message(keygen_msg_6)?;
        println!("[BOB => ALICE] Opens commitment to Q̂");
        let (alice, sign_msg_1) = alice.receive_message(keygen_msg_7)?;

        // Nonce Generation
        println!("[ALICE => BOB] Comm(R₂, nizk(R₂))");
        let (bob, sign_msg_2) = bob.receive_message(sign_msg_1);
        println!("[BOΒ => ALICE] R₁, nizk(R₁)");
        let (alice, sign_msg_3) = alice.receive_message(sign_msg_2)?;
        println!("[BOΒ => ALICE] R₁, nizk(R₁), R₃, c₃");
        let (bob, sign_msg_4) = bob.receive_message(sign_msg_3)?;
        println!("[BOΒ => ALICE] s′′");
        let (_alice, blockchain_msg) = alice.receive_message(sign_msg_4)?;
        println!("[ALICE => BLOCKCHAIN] s (i.e broadcasts the signed transaction)");
        let (bob, _) = bob.receive_message(blockchain_msg)?;
        println!("BOΒ learns {:?}", bob.y);
    };

    Ok(())
}
