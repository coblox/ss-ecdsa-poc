#![allow(non_snake_case)]
use bitcoin_hashes::{self, Hash};
use merlin::Transcript;
use secp256k1::Message;
use ss_ecdsa_poc::{alice::Alice1, bob::Bob1, SSEcdsaTranscript};

pub fn main() -> Result<(), ()> {
    {
        // KEY GENERATION
        // Y is the public key Bob wants to know the private key for
        let mut alice_transcript = Transcript::new(b"ss_ecdsa");
        let mut bob_transcript = Transcript::new(b"ss_ecdsa");

        println!("ALICE STATE: {}", alice_transcript.state_id());
        println!("BOB STATE: {}", bob_transcript.state_id());

        let (bob, keygen_msg_1) = Bob1::new(&mut bob_transcript);
        println!("[BOB => ALICE] commitment to points and proofs",);
        let (alice, keygen_msg_2) = Alice1::new(&mut alice_transcript, keygen_msg_1);
        println!("[ALICE => BOB] points and proofs");
        let (bob, keygen_msg_3) = bob.receive_message(&mut bob_transcript, keygen_msg_2)?;
        println!("[BOB => ALICE] Opens commitment and sends encrypted keys");
        let (alice, pdl_msg_1) = alice.receive_message(&mut alice_transcript, keygen_msg_3)?;
        println!("[ALICE => BOB] PDL challenge");
        let (bob, pdl_msg_2) = bob.receive_message(pdl_msg_1)?;
        println!("[BOB => Alice] PDL commited response");
        let (alice, pdl_msg_3) = alice.receive_message(pdl_msg_2);
        println!("[Alice => Bob] PDL reveal challenge");
        let (bob, pdl_msg_4) = bob.receive_message(pdl_msg_3)?;
        println!("[Bob => Alice] PDL open commited response");
        let (alice, sign_msg_1) = alice.receive_message(pdl_msg_4)?;
        // println!("[Alice => Bob] Encrypted partial sigantures");
        // let (bob, sign_msg_2) = bob.receive_message(sign_msg_1)?;

        // // println!("[ALICE => BOB] the lock {:?}", Y);

        // // println!("[BOB => ALICE] His public key Comm(X₁, nizk(X₁))");

        // println!("[ALICE => BOB] X₂, nizk(X₂)");

        // println!("[BOB => ALICE] Opens his commitment, sends c = PaillierEncrypt(x₁),
        // N  and proofs for N"); let (alice, pdl_msg_2) =
        // alice.receive_message(pdl_msg_1)?; println!("[ALICE => BOB] PDL:
        // challenge c′"); let (bob, keygen_msg_5) =
        // bob.receive_message(keygen_msg_4)?; println!("[BOB => ALICE] PDL:
        // Comm(Q̂)"); let (alice, keygen_msg_6) =
        // alice.receive_message(keygen_msg_5); println!("[ALICE => BOB] PDL:
        // Reveal a,b used to produce c′"); let (bob, keygen_msg_7) =
        // bob.receive_message(keygen_msg_6)?; println!("[BOB => ALICE] PDL:
        // Opens commitment to Q̂"); let (alice, sign_msg_1) =
        // alice.receive_message(keygen_msg_7)?;

        // // Nonce Generation
        // println!("[ALICE => BOB] Comm(R₂, nizk(R₂))");
        // let (bob, sign_msg_2) = bob.receive_message(sign_msg_1);
        // println!("[BOΒ => ALICE] R₁, nizk(R₁)");
        // let (alice, sign_msg_3) = alice.receive_message(sign_msg_2)?;
        // println!("[BOΒ => ALICE] R₁, nizk(R₁), R₃, c₃");
        // let (bob, sign_msg_4) = bob.receive_message(sign_msg_3)?;
        // println!("[BOΒ => ALICE] s′′");
        // let (_alice, blockchain_msg) = alice.receive_message(sign_msg_4)?;
        // println!("[ALICE => BLOCKCHAIN] s (i.e broadcasts the signed transaction)");
        // let (bob, _) = bob.receive_message(blockchain_msg)?;
        // println!("BOΒ learns {:?}", bob.y);
    };

    Ok(())
}
