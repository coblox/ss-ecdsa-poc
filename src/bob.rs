use crate::{
    commited_nizk::{commit_nizk, Opening},
    ecdsa,
    messages::*,
    nizk_sigma_proof::{CompactProof, Proof, StatementKind, Witness},
    KeyPair, SSEcdsaTranscript,
};
use ecdsa::Signature;

use curv::{
    arithmetic::traits::Modulo,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use merlin::Transcript;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

pub struct BobKeys {
    pub x_beta: KeyPair,
    pub x_alpha: KeyPair,
    pub r_beta_redeem: KeyPair,
    pub r_beta_refund: KeyPair,
}

impl BobKeys {
    pub fn new_random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        Self {
            x_alpha: KeyPair::new_random(rng),
            x_beta: KeyPair::new_random(rng),
            r_beta_redeem: KeyPair::new_random(rng),
            r_beta_refund: KeyPair::new_random(rng),
        }
    }
}

pub struct Bob1 {
    commitment_opening: Opening<CompactProof>,
    keys: BobKeys,
}

impl Bob1 {
    pub fn new(transcript: &mut Transcript) -> (Bob1, KeyGenMsg1) {
        let g = GE::generator();
        let mut rng = transcript.rng();
        let keys = BobKeys::new_random(&mut rng);

        let keygen_witness = vec![
            Witness {
                x: keys.x_alpha.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"X_alpha_bob",
            },
            Witness {
                x: keys.x_beta.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"X_beta_bob",
            },
            Witness {
                x: keys.r_beta_redeem.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"R_beta_redeem_bob",
            },
            Witness {
                x: keys.r_beta_refund.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"R_beta_refund_bob",
            },
        ];

        let (commitment, commitment_opening) =
            commit_nizk::<CompactProof>(transcript, b"ssecdsa_keygen_bob", &keygen_witness);

        (
            Self {
                commitment_opening,
                keys,
            },
            KeyGenMsg1 { commitment },
        )
    }

    pub fn receive_message(
        self,
        transcript: &mut Transcript,
        alice_keygen: KeyGenMsg2,
    ) -> Result<(Bob2, KeyGenMsg3), ()> {
        let alice_points = alice_keygen.points.clone();
        let alice_proof = CompactProof::from(alice_keygen);

        if !alice_proof.verify(transcript, b"ssecdsa_keygen_alice") {
            eprintln!("Failed to verify Alice's proofs");
            return Err(());
        }

        let pq_and_c = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(
            &self.keys.x_beta.into(),
        );

        let range_proof = party_one::PaillierKeyPair::generate_range_proof(
            &pq_and_c,
            &party_one::Party1Private::set_private_key(&self.keys.x_beta.into(), &pq_and_c),
        );

        let paillier_correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&pq_and_c);

        let N_and_c = party_two::PaillierPublic {
            ek: pq_and_c.ek.clone(),
            encrypted_secret_share: pq_and_c.encrypted_share.clone(),
        };

        let X_beta = alice_points.X_beta.clone() * &self.keys.x_beta.secret_key;

        Ok((
            Bob2 {
                keys: self.keys,
                alice_points,
                pq_and_c,
                X_beta,
            },
            KeyGenMsg3 {
                N_and_c,
                commitment_opening: self.commitment_opening.into(),
                paillier_range_proof: range_proof,
                paillier_correct_key_proof,
            },
        ))
    }
}

pub struct Bob2 {
    keys: BobKeys,
    alice_points: AlicePoints,
    pq_and_c: party_one::PaillierKeyPair,
    X_beta: GE,
}

impl Bob2 {
    pub fn receive_message(self, msg: PdlMsg1) -> Result<(Bob3, PdlMsg2), ()> {
        let (keygen_msg_5, pdl_decommit, alpha) = party_one::PaillierKeyPair::pdl_first_stage(
            &party_one::Party1Private::set_private_key(&self.keys.x_beta.into(), &self.pq_and_c),
            &msg,
        );

        Ok((
            Bob3 {
                keys: self.keys,
                alice_points: self.alice_points,
                pq_and_c: self.pq_and_c,
                X_beta: self.X_beta,
                pdl_first_message: msg,
                pdl_decommit,
                alpha,
            },
            keygen_msg_5,
        ))
    }
}

pub struct Bob3 {
    keys: BobKeys,
    alice_points: AlicePoints,
    pq_and_c: party_one::PaillierKeyPair,
    X_beta: GE,
    pdl_decommit: party_one::PDLdecommit,
    pdl_first_message: party_two::PDLFirstMessage,
    alpha: BigInt,
}

impl Bob3 {
    pub fn receive_message(self, msg: PdlMsg3) -> Result<(Bob4, PdlMsg4), ()> {
        let pdl_msg_4 = party_one::PaillierKeyPair::pdl_second_stage(
            &self.pdl_first_message,
            &msg,
            party_one::Party1Private::set_private_key(&self.keys.x_beta.into(), &self.pq_and_c),
            self.pdl_decommit,
            self.alpha,
        )
        .map_err(|_| ())?;

        Ok((
            Bob4 {
                keys: self.keys,
                alice_points: self.alice_points,
                X_beta: self.X_beta,
                pq_and_c: self.pq_and_c,
            },
            pdl_msg_4,
        ))
    }
}

pub struct Bob4 {
    keys: BobKeys,
    alice_points: AlicePoints,
    X_beta: GE,
    pq_and_c: party_one::PaillierKeyPair,
}

use paillier::{traits::Decrypt, DecryptionKey, Paillier, RawCiphertext, RawPlaintext};

impl Bob4 {
    pub fn receive_message(self, msg: SignMsg1) -> Result<(Bob5, SignMsg2), ()> {
        let s_beta_redeem_missing_y = {
            let R_beta_redeem = self.alice_points.R3 * self.keys.r_beta_redeem.secret_key;
            let s_tag = Self::extract_partial_sig(
                &self.pq_and_c.dk,
                &msg.c_beta_redeem_missing_y_and_bob_R,
                self.X_beta,
                R_beta_redeem,
                self.alice_points.R_beta_redeem,
                beta_redeem_tx(),
            )
            .map_err(|_| eprintln!("beta redeem verify failed"))?;
            s_tag * self.keys.r_beta_redeem.secret_key.invert()
        };

        let sig_beta_refund = {
            let R_beta_refund =
                self.alice_points.R_beta_refund * &self.keys.r_beta_refund.secret_key;
            let s_tag = Self::extract_partial_sig(
                &self.pq_and_c.dk,
                &msg.c_beta_refund_missing_bob_R,
                self.X_beta,
                R_beta_refund,
                self.alice_points.R_beta_refund,
                beta_refund_tx(),
            )
            .map_err(|_| eprintln!("beta refund verify failed"))?;
            let s_beta_refund = s_tag * self.keys.r_beta_refund.secret_key.invert();
            ecdsa::normalize_and_verify(
                &beta_refund_tx(),
                &self.X_beta,
                &s_beta_refund,
                &R_beta_refund,
            )?
        };

        Ok((
            Bob5 {
                X_beta: self.X_beta,
                s_beta_redeem_missing_y,
                Y: self.alice_points.Y,
                sig_beta_refund,
            },
            SignMsg2 {
                s_beta_redeem_missing_y,
            },
        ))
    }

    fn extract_partial_sig(
        paillier_key: &DecryptionKey,
        c: &BigInt,
        X: GE,
        R: GE,
        R_partial: GE,
        msg: secp256k1::Message,
    ) -> Result<FE, ()> {
        let tmp: RawPlaintext = Paillier::decrypt(paillier_key, &RawCiphertext::from(c.clone()));
        let s_tag: FE = ECScalar::from(&tmp.0);
        let g = GE::generator();
        let rx: FE = ECScalar::from(&R.x_coor().unwrap());
        let m: FE = ECScalar::from(&BigInt::from(&msg[..]));

        // Check that alice didn't send us an invalid s_tag
        if R_partial * s_tag == X * rx + g * m {
            Ok(s_tag)
        } else {
            Err(())
        }
    }
}

pub struct Bob5 {
    X_beta: GE,
    s_beta_redeem_missing_y: FE,
    Y: GE,
    #[allow(dead_code)]
    sig_beta_refund: Signature,
}

impl Bob5 {
    pub fn receive_message(self, msg: BlockchainMsg) -> Result<(Bob7, ()), ()> {
        if !ecdsa::verify(
            &beta_redeem_tx(),
            &msg.sig_beta_redeem.Rx,
            &msg.sig_beta_redeem.s,
            &self.X_beta,
        ) {
            return Err(());
        }

        Ok((
            Bob7 {
                y: self.extract_y(msg.sig_beta_redeem.s)?,
            },
            (),
        ))
    }

    fn extract_y(&self, s: FE) -> Result<FE, ()> {
        let q = FE::q();
        let y_maybe = s.invert() * self.s_beta_redeem_missing_y;
        let Y_maybe: GE = GE::generator() * y_maybe;
        let Y = &self.Y;

        // NOTE: There may be faster ways of checking this
        if Y_maybe.x_coor().unwrap() == Y.x_coor().unwrap() {
            if Y_maybe.y_coor().unwrap() != Y.y_coor().unwrap() {
                Ok(ECScalar::from(&BigInt::mod_sub(
                    &q,
                    &y_maybe.to_big_int(),
                    &q,
                )))
            } else {
                Ok(y_maybe)
            }
        } else {
            Err(())
        }
    }
}

pub struct Bob7 {
    pub y: FE,
}
