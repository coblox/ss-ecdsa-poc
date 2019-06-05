use crate::{
    commited_nizk::{Opener, Opening},
    ecdsa,
    messages::*,
    nizk_sigma::{CompactProof, LabelledStatement, Proof, Statement, StatementKind, Witness},
    KeyPair, SSEcdsaTranscript,
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, GE,
};
use merlin::Transcript;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

pub struct AliceKeys {
    pub y: KeyPair,
    pub x_beta: KeyPair,
    pub r_beta_redeem: KeyPair,
    pub r_beta_refund: KeyPair,
}

impl AliceKeys {
    pub fn new_random(rng: &mut (impl rand::RngCore + rand::CryptoRng)) -> Self {
        Self {
            y: KeyPair::new_random(rng),
            x_beta: KeyPair::new_random(rng),
            r_beta_redeem: KeyPair::new_random(rng),
            r_beta_refund: KeyPair::new_random(rng),
        }
    }
}

pub struct Alice1 {
    bob_commitment: Opener,
    keys: AliceKeys,
}

impl Alice1 {
    pub fn new(transcript: &mut Transcript, keygen_msg_1: KeyGenMsg1) -> (Alice1, KeyGenMsg2) {
        let g = GE::generator();
        let bob_commitment = keygen_msg_1
            .commitment
            .receive(transcript, b"ssecdsa_keygen_bob");

        let mut rng = transcript.rng();

        let keys = AliceKeys::new_random(&mut rng);

        let keygen_witness = vec![
            Witness {
                x: keys.x_beta.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"X_beta_alice",
            },
            Witness {
                x: keys.r_beta_redeem.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"R_beta_redeem_alice",
            },
            Witness {
                x: keys.r_beta_refund.secret_key,
                kind: StatementKind::Schnorr { g },
                label: b"R_beta_refund_alice",
            },
            Witness {
                x: keys.y.secret_key,
                kind: StatementKind::DDH {
                    g,
                    h: keys.r_beta_redeem.public_key,
                },
                label: b"Y",
            },
        ];

        let proof = CompactProof::prove(transcript, b"ssecdsa_keygen_alice", &keygen_witness);

        (
            Alice1 {
                bob_commitment,
                keys,
            },
            KeyGenMsg2::from(proof),
        )
    }

    pub fn receive_message(self, msg: KeyGenMsg3) -> Result<(Alice2, PdlMsg1), ()> {
        let bob_points = msg.commitment_opening.points.clone();
        let opening = Self::apply_labels_to_opening(msg.commitment_opening);
        self.bob_commitment
            .open(opening)
            .map_err(|_| eprintln!("Failed to verify Bob's proof"))?;

        let X_beta = bob_points.X_beta * self.keys.x_beta.secret_key;

        party_two::PaillierPublic::verify_ni_proof_correct_key(
            msg.paillier_correct_key_proof,
            &msg.N_and_c.ek,
        )
        .map_err(|_| eprintln!("Failed to verify ni_proof_correct_key"))?;

        // XXX: THIS CAN PANIC IF THE FIRST ARGUMENT DOESN'T MATCH WITH THE SECOND --
        // ARRRG
        // HACK: ARRG STOP THE RANGE PROOF FOR NOW WHICH FAILS NON-DETERMINISTICALLY
        // let range_proof = &msg.paillier_range_proof;
        // party_two::PaillierPublic::verify_range_proof(&msg.N_and_c, range_proof)
        //     .map_err(|_| eprintln!("Failed range proof "))?;

        let (pdl_first_message, pdl_challenge) = msg.N_and_c.pdl_challenge(&bob_points.X_beta);

        Ok((
            Alice2 {
                keys: self.keys,
                bob_points,
                X_beta,
                N_and_c: msg.N_and_c,
                pdl_challenge,
            },
            pdl_first_message,
        ))
    }

    fn apply_labels_to_opening(opening: CommitmentOpening) -> Opening<CompactProof> {
        let points = opening.points;
        let responses = opening.responses;
        let g = GE::generator();
        Opening {
            nonce: opening.nonce,
            proof: CompactProof {
                challenge: opening.challenge,
                responses: vec![
                    (
                        responses.X_alpha,
                        LabelledStatement {
                            label: b"X_alpha_bob",
                            statement: Statement::Schnorr {
                                g,
                                gx: points.X_alpha,
                            },
                        },
                    ),
                    (
                        responses.X_beta,
                        LabelledStatement {
                            label: b"X_beta_bob",
                            statement: Statement::Schnorr {
                                g,
                                gx: points.X_beta,
                            },
                        },
                    ),
                    (
                        responses.R_beta_redeem,
                        LabelledStatement {
                            label: b"R_beta_redeem_bob",
                            statement: Statement::Schnorr {
                                g,
                                gx: points.R_beta_redeem,
                            },
                        },
                    ),
                    (
                        responses.R_beta_refund,
                        LabelledStatement {
                            label: b"R_beta_refund_bob",
                            statement: Statement::Schnorr {
                                g,
                                gx: points.R_beta_refund,
                            },
                        },
                    ),
                ],
            },
        }
    }
}

pub struct Alice2 {
    keys: AliceKeys,
    N_and_c: party_two::PaillierPublic,
    bob_points: BobPoints,
    X_beta: GE,
    pdl_challenge: party_two::PDLchallenge,
}

impl Alice2 {
    pub fn receive_message(self, msg: PdlMsg2) -> (Alice3, PdlMsg3) {
        let decommit = party_two::PaillierPublic::pdl_decommit_c_tag_tag(&self.pdl_challenge);
        (
            Alice3 {
                X_beta: self.X_beta,
                N_and_c: self.N_and_c,
                pdl_first_message: msg,
                pdl_challenge: self.pdl_challenge,
                keys: self.keys,
                bob_points: self.bob_points,
            },
            decommit,
        )
    }
}

pub struct Alice3 {
    X_beta: GE,
    N_and_c: party_two::PaillierPublic,
    pdl_challenge: party_two::PDLchallenge,
    pdl_first_message: party_one::PDLFirstMessage,
    keys: AliceKeys,
    bob_points: BobPoints,
}

impl Alice3 {
    pub fn receive_message(self, msg: PdlMsg4) -> Result<(Alice4, SignMsg1), ()> {
        party_two::PaillierPublic::verify_pdl(&self.pdl_challenge, &self.pdl_first_message, &msg)?;

        let (c_beta_redeem_missing_y_and_bob_R, R_beta_redeem) = {
            // FIXME: Remove this by rewriting party_two::PartialSig::compute
            // We contrive the nonce point that makes compute() dooes the thing we want
            let R_contrived = self.bob_points.R_beta_redeem * self.keys.y.secret_key;

            let c3 = party_two::PartialSig::compute(
                &self.N_and_c.ek,
                &self.N_and_c.encrypted_secret_share,
                &party_two::Party2Private::set_private_key(&self.keys.x_beta.into()),
                &self.keys.r_beta_redeem.into(),
                &R_contrived,
                &BigInt::from(&beta_redeem_tx()[..]),
            )
            .c3;

            // This is what compute will actually do this inside -- but we need it for later
            // to compute it here too
            let R_beta_redeem = R_contrived * self.keys.r_beta_redeem.secret_key;

            (c3, R_beta_redeem)
        };

        let c_beta_refund_missing_bob_R = party_two::PartialSig::compute(
            &self.N_and_c.ek,
            &self.N_and_c.encrypted_secret_share,
            &party_two::Party2Private::set_private_key(&self.keys.x_beta.into()),
            &self.keys.r_beta_refund.into(),
            &self.bob_points.R_beta_refund,
            &BigInt::from(&beta_refund_tx()[..]),
        )
        .c3;

        Ok((
            Alice4 {
                keys: self.keys,
                X_beta: self.X_beta,
                R_beta_redeem,
            },
            SignMsg1 {
                c_beta_redeem_missing_y_and_bob_R,
                c_beta_refund_missing_bob_R,
            },
        ))
    }
}

pub struct Alice4 {
    keys: AliceKeys,
    R_beta_redeem: GE,
    X_beta: GE,
}

impl Alice4 {
    pub fn receive_message(self, msg: SignMsg2) -> Result<((), BlockchainMsg), ()> {
        let s_beta_redeem = msg.s_beta_redeem_missing_y * self.keys.y.secret_key.invert();
        let sig_beta_redeem = ecdsa::normalize_and_verify(
            &beta_redeem_tx(),
            &self.X_beta,
            &s_beta_redeem,
            &self.R_beta_redeem,
        )?;
        Ok(((), BlockchainMsg { sig_beta_redeem }))
    }
}
