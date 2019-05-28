use crate::{ecdsa, messages::*};
use curv::{
    arithmetic::traits::Modulo,
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

#[derive(Debug)]
pub struct Bob1 {
    m: secp256k1::Message,
    Y: GE,
    commitment_opening: party_one::CommWitness,
    key_half: party_one::EcKeyPair,
}

impl Bob1 {
    pub fn new(Y: GE, m: secp256k1::Message) -> (Bob1, KeyGenMsg1) {
        let (commited_public_key, commitment_opening, key_half) =
            party_one::KeyGenFirstMsg::create_commitments();
        (
            Self {
                m,
                Y,
                commitment_opening,
                key_half,
            },
            commited_public_key,
        )
    }

    pub fn receive_message(self, alice_keygen: KeyGenMsg2) -> Result<(Bob2, KeyGenMsg3), ()> {
        let commitment_opening = party_one::KeyGenSecondMsg::verify_and_decommit(
            self.commitment_opening,
            &alice_keygen.d_log_proof,
        )
        .map_err(|_| ())?;

        let pq_and_c =
            party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&self.key_half);
        let x1 = party_one::Party1Private::set_private_key(&self.key_half, &pq_and_c);

        let range_proof = party_one::PaillierKeyPair::generate_range_proof(&pq_and_c, &x1);

        let paillier_correct_key_proof =
            party_one::PaillierKeyPair::generate_ni_proof_correct_key(&pq_and_c);

        let N_and_c = party_two::PaillierPublic {
            ek: pq_and_c.ek.clone(),
            encrypted_secret_share: pq_and_c.encrypted_share.clone(),
        };

        let X = party_one::compute_pubkey(&x1, &alice_keygen.public_share);

        Ok((
            Bob2 {
                m: self.m,
                Y: self.Y,
                x1,
                pq_and_c,
                X,
            },
            KeyGenMsg3 {
                N_and_c,
                commitment_opening,
                paillier_range_proof: range_proof,
                paillier_correct_key_proof,
            },
        ))
    }
}

pub struct Bob2 {
    m: secp256k1::Message,
    Y: GE,
    x1: party_one::Party1Private,
    pq_and_c: party_one::PaillierKeyPair,
    X: GE,
}

impl Bob2 {
    pub fn receive_message(self, msg: KeyGenMsg4) -> Result<(Bob3, KeyGenMsg5), ()> {
        let (keygen_msg_5, pdl_decommit, alpha) =
            party_one::PaillierKeyPair::pdl_first_stage(&self.x1, &msg);

        Ok((
            Bob3 {
                m: self.m,
                Y: self.Y,
                x1: self.x1,
                pq_and_c: self.pq_and_c,
                X: self.X,
                pdl_first_message: msg,
                pdl_decommit,
                alpha,
            },
            keygen_msg_5,
        ))
    }
}

pub struct Bob3 {
    m: secp256k1::Message,
    Y: GE,
    x1: party_one::Party1Private,
    pq_and_c: party_one::PaillierKeyPair,
    X: GE,
    pdl_decommit: party_one::PDLdecommit,
    pdl_first_message: party_two::PDLFirstMessage,
    alpha: BigInt,
}

impl Bob3 {
    pub fn receive_message(self, msg: KeyGenMsg6) -> Result<(Bob4, KeyGenMsg7), ()> {
        let keygen_msg_7 = party_one::PaillierKeyPair::pdl_second_stage(
            &self.pdl_first_message,
            &msg,
            self.x1.clone(),
            self.pdl_decommit,
            self.alpha,
        )
        .map_err(|_| ())?;

        Ok((
            Bob4 {
                m: self.m,
                Y: self.Y,
                X: self.X,
                pq_and_c: self.pq_and_c,
            },
            keygen_msg_7,
        ))
    }
}

pub struct Bob4 {
    m: secp256k1::Message,
    Y: GE,
    X: GE,
    pq_and_c: party_one::PaillierKeyPair,
}

impl Bob4 {
    pub fn receive_message(self, msg: SignMsg1) -> (Bob5, SignMsg2) {
        let (sign_msg_2, r1) = party_one::EphKeyGenFirstMsg::create();

        (
            Bob5 {
                m: self.m,
                Y: self.Y,
                X: self.X,
                pq_and_c: self.pq_and_c,
                alice_commitment: msg,
                r1,
            },
            sign_msg_2,
        )
    }
}

pub struct Bob5 {
    m: secp256k1::Message,
    Y: GE,
    X: GE,
    pq_and_c: party_one::PaillierKeyPair,
    alice_commitment: party_two::EphKeyGenFirstMsg,
    r1: party_one::EphEcKeyPair,
}

impl Bob5 {
    pub fn receive_message(self, msg: SignMsg3) -> Result<(Bob6, SignMsg4), ()> {
        use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
        let _ = party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &self.alice_commitment,
            &msg.commitment_opening,
        )
        .map_err(|_| ())?;

        let R2 = msg.commitment_opening.comm_witness.public_share;

        msg.R3_DH_proof
            .verify(&ECDDHStatement {
                g1: ECPoint::generator(),
                h1: self.Y,
                g2: R2,
                h2: msg.R3,
            })
            .map_err(|_| ())?;

        let s_tag = self.extract_s_tag(&msg)?;
        let s_tag_tag = s_tag * self.r1.secret_share.invert();

        Ok((
            Bob6 {
                m: self.m,
                Y: self.Y,
                X: self.X,
                s_tag_tag: s_tag_tag.clone(),
            },
            SignMsg4 { s_tag_tag },
        ))
    }

    fn extract_s_tag(&self, msg: &SignMsg3) -> Result<FE, ()> {
        use paillier::{traits::Decrypt, Paillier, RawCiphertext};
        let s_tag: FE =
            ECScalar::from(&Paillier::decrypt(&self.pq_and_c.dk, &RawCiphertext::from(&msg.c3)).0);
        let g = GE::generator();
        let R2 = msg.commitment_opening.comm_witness.public_share;
        let R = msg.R3 * self.r1.secret_share;
        let rx: FE = ECScalar::from(&R.x_coor().unwrap());
        let m: FE = ECScalar::from(&BigInt::from(&self.m[..]));

        // Check that alice didn't send us an invalid s_tag
        if R2 * s_tag == self.X * rx + g * m {
            Ok(s_tag)
        } else {
            Err(())
        }
    }
}

pub struct Bob6 {
    m: secp256k1::Message,
    Y: GE,
    X: GE,
    s_tag_tag: FE,
}

impl Bob6 {
    pub fn receive_message(self, msg: BlockchainMsg) -> Result<(Bob7, ()), ()> {
        if !ecdsa::verify(&self.m, &msg.signature.Rx, &msg.signature.s, &self.X) {
            return Err(());
        }

        Ok((
            Bob7 {
                y: self.extract_y(msg.signature.s)?,
            },
            (),
        ))
    }

    fn extract_y(&self, s: FE) -> Result<FE, ()> {
        let q = FE::q();
        let y_maybe = s.invert() * self.s_tag_tag;
        let Y_maybe: GE = GE::generator() * y_maybe;

        if Y_maybe.x_coor().unwrap() == self.Y.x_coor().unwrap() {
            if Y_maybe.y_coor().unwrap() != self.Y.y_coor().unwrap() {
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
