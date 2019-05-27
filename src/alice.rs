use crate::{ecdsa, messages::*};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

#[derive(Debug, Clone, Copy)]
pub struct KeyPair {
    pub secret_key: FE,
    pub public_key: GE,
}

impl KeyPair {
    pub fn new_random() -> Self {
        let base: GE = GE::generator();
        let secret_key = FE::new_random();
        let public_key = base * secret_key;
        Self {
            secret_key,
            public_key,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Alice1 {
    m: BigInt,
    pub y: KeyPair,
}

impl Alice1 {
    pub fn new(m: BigInt) -> (Alice1, GE) {
        let _self = Alice1 {
            y: KeyPair::new_random(),
            m,
        };

        (_self.clone(), _self.y.public_key)
    }

    pub fn receive_message(
        self,
        bob_keygen_first_msg: KeyGenMsg1,
    ) -> (Alice2, party_two::KeyGenFirstMsg) {
        let (alice_keygen_first_msg, x2) = party_two::KeyGenFirstMsg::create();
        (
            Alice2 {
                m: self.m,
                y: self.y,
                bob_keygen_first_msg,
                x2,
            },
            alice_keygen_first_msg,
        )
    }
}

pub struct Alice2 {
    m: BigInt,
    y: KeyPair,
    x2: party_two::EcKeyPair,
    bob_keygen_first_msg: party_one::KeyGenFirstMsg,
}

impl Alice2 {
    pub fn receive_message(self, keygen_msg_3: KeyGenMsg3) -> Result<(Alice3, KeyGenMsg4), ()> {
        let _ = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &self.bob_keygen_first_msg,
            &keygen_msg_3.commitment_opening,
        )
        .map_err(|_| ())?;
        let bob_key = &keygen_msg_3.commitment_opening.comm_witness.public_share;
        let X = party_two::compute_pubkey(&self.x2, bob_key);

        party_two::PaillierPublic::verify_ni_proof_correct_key(
            keygen_msg_3.paillier_correct_key_proof,
            &keygen_msg_3.N_and_c.ek,
        )
        .map_err(|_| ())?;

        party_two::PaillierPublic::verify_range_proof(
            &keygen_msg_3.N_and_c,
            &keygen_msg_3.paillier_range_proof,
        )
        .map_err(|_| ())?;

        let (pdl_first_message, pdl_challenge) = keygen_msg_3.N_and_c.pdl_challenge(bob_key);

        Ok((
            Alice3 {
                m: self.m,
                y: self.y,
                X,
                N_and_c: keygen_msg_3.N_and_c,
                pdl_challenge,
                x2: self.x2,
            },
            pdl_first_message,
        ))
    }
}

pub struct Alice3 {
    m: BigInt,
    y: KeyPair,
    X: GE,
    x2: party_two::EcKeyPair,
    N_and_c: party_two::PaillierPublic,
    pdl_challenge: party_two::PDLchallenge,
}

impl Alice3 {
    pub fn receive_message(self, msg: KeyGenMsg5) -> (Alice4, KeyGenMsg6) {
        let decommit = party_two::PaillierPublic::pdl_decommit_c_tag_tag(&self.pdl_challenge);
        (
            Alice4 {
                m: self.m,
                y: self.y,
                X: self.X,
                N_and_c: self.N_and_c,
                x2: self.x2,
                pdl_first_message: msg,
                pdl_challenge: self.pdl_challenge,
            },
            decommit,
        )
    }
}

pub struct Alice4 {
    m: BigInt,
    y: KeyPair,
    X: GE,
    x2: party_two::EcKeyPair,
    N_and_c: party_two::PaillierPublic,
    pdl_challenge: party_two::PDLchallenge,
    pdl_first_message: party_one::PDLFirstMessage,
}

impl Alice4 {
    pub fn receive_message(self, key_gen_final: KeyGenMsg7) -> Result<(Alice5, SignMsg1), ()> {
        party_two::PaillierPublic::verify_pdl(
            &self.pdl_challenge,
            &self.pdl_first_message,
            &key_gen_final,
        )?;
        let (sign_msg_1, R2_commitment_opening, r2) =
            party_two::EphKeyGenFirstMsg::create_commitments();
        Ok((
            Alice5 {
                m: self.m,
                y: self.y,
                X: self.X,
                x2: self.x2,
                N_and_c: self.N_and_c,
                R2_commitment_opening,
                r2,
            },
            sign_msg_1,
        ))
    }
}

pub struct Alice5 {
    m: BigInt,
    y: KeyPair,
    X: GE,
    x2: party_two::EcKeyPair,
    N_and_c: party_two::PaillierPublic,
    r2: party_two::EphEcKeyPair,
    R2_commitment_opening: party_two::EphCommWitness,
}

impl Alice5 {
    pub fn receive_message(self, msg: SignMsg2) -> Result<(Alice6, SignMsg3), ()> {
        use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
        let commitment_opening =
            party_two::EphKeyGenSecondMsg::verify_and_decommit(self.R2_commitment_opening, &msg)
                .map_err(|_| ())?;

        let R1 = msg.public_share;

        let r3 = self.r2.secret_share * self.y.secret_key;
        let R3 = GE::generator() * r3;
        let R = R1 * r3;

        let R3_DH_proof = {
            let R3_DH_statement = ECDDHStatement {
                g1: ECPoint::generator(),
                h1: self.y.public_key.clone(),
                g2: self.r2.public_share,
                h2: R3,
            };

            ECDDHProof::prove(
                &ECDDHWitness {
                    x: self.y.secret_key,
                },
                &R3_DH_statement,
            )
        };

        let c3 = party_two::PartialSig::compute(
            &self.N_and_c.ek,
            &self.N_and_c.encrypted_secret_share,
            &party_two::Party2Private::set_private_key(&self.x2),
            &self.r2,
            &(R1 * self.y.secret_key),
            &self.m,
        )
        .c3;

        Ok((
            Alice6 {
                m: self.m,
                y: self.y,
                X: self.X,
                R,
            },
            SignMsg3 {
                commitment_opening,
                R3,
                R3_DH_proof,
                c3,
            },
        ))
    }
}

pub struct Alice6 {
    m: BigInt,
    y: KeyPair,
    X: GE,
    R: GE,
}

impl Alice6 {
    pub fn receive_message(self, msg: SignMsg4) -> Result<((), BlockchainMsg), ()> {
        let signature = self.compute_signature(msg.s_tag_tag)?;
        Ok(((), BlockchainMsg { signature }))
    }

    fn compute_signature(&self, s_tag_tag: BigInt) -> Result<party_one::Signature, ()> {
        let s_tag_tag: FE = ECScalar::from(&s_tag_tag);
        let mut s = (s_tag_tag * self.y.secret_key.invert()).to_big_int();
        let neg_s = FE::q() - s.clone();
        if s > neg_s {
            s = neg_s;
        }
        let rx = self.R.x_coor().unwrap();

        if !ecdsa::verify(&self.m, &rx, &s, &self.X) {
            return Err(());
        }

        let signature = party_one::Signature { r: rx, s };

        Ok(signature)
    }
}
