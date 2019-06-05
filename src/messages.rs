use crate::{
    commited_nizk::{Commitment, Opening},
    nizk_sigma_proof::{CompactProof, LabelledStatement, Statement},
};
use bitcoin_hashes::Hash;
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};

#[derive(Clone, Debug)]
pub struct AlicePoints {
    pub X_beta: GE,
    pub R_beta_redeem: GE,
    pub R_beta_refund: GE,
    pub R3: GE,
    pub Y: GE,
}

#[derive(Clone, Debug)]
pub struct AliceResponses {
    pub X_beta: FE,
    pub R_beta_redeem: FE,
    pub R_beta_refund: FE,
    pub Y_R3: FE,
}

#[derive(Clone, Debug)]
pub struct BobPoints {
    pub X_alpha: GE,
    pub X_beta: GE,
    pub R_beta_redeem: GE,
    pub R_beta_refund: GE,
}

#[derive(Clone, Debug)]
pub struct BobResponses {
    pub X_alpha: FE,
    pub X_beta: FE,
    pub R_beta_redeem: FE,
    pub R_beta_refund: FE,
}

#[derive(Clone, Debug)]
pub struct CommitmentOpening {
    pub nonce: [u8; 32],
    pub points: BobPoints,
    pub challenge: FE,
    pub responses: BobResponses,
}

macro_rules! extract_schnorr {
    ($proof:expr, $label:expr) => {
        match $proof.get_response($label) {
            (response, Statement::Schnorr { gx, .. }) => (gx, response),
            _ => panic!("only use for schnorr"),
        }
    };
}

impl From<CompactProof> for KeyGenMsg2 {
    fn from(proof: CompactProof) -> Self {
        let (Y, R3, Y_R3_response) = match proof.get_response(b"Y") {
            (response, Statement::DDH { g, gx, h, hx }) => (gx, hx, response),
            _ => unreachable!("R3 is a DDH proof"),
        };
        let (X_beta, X_beta_response) = extract_schnorr!(proof, b"X_beta_alice");
        let (R_beta_redeem, R_beta_redeem_response) =
            extract_schnorr!(proof, b"R_beta_redeem_alice");
        let (R_beta_refund, R_beta_refund_response) =
            extract_schnorr!(proof, b"R_beta_refund_alice");
        KeyGenMsg2 {
            challenge: proof.challenge,
            points: AlicePoints {
                Y,
                X_beta,
                R_beta_redeem,
                R_beta_refund,
                R3,
            },
            responses: AliceResponses {
                X_beta: X_beta_response,
                R_beta_redeem: R_beta_redeem_response,
                R_beta_refund: R_beta_refund_response,
                Y_R3: Y_R3_response,
            },
        }
    }
}

impl From<KeyGenMsg2> for CompactProof {
    fn from(msg: KeyGenMsg2) -> CompactProof {
        let points = msg.points;
        let responses = msg.responses;
        let g = GE::generator();
        CompactProof {
            challenge: msg.challenge,
            responses: vec![
                (
                    responses.X_beta,
                    LabelledStatement {
                        label: b"X_beta_alice",
                        statement: Statement::Schnorr {
                            g,
                            gx: points.X_beta,
                        },
                    },
                ),
                (
                    responses.R_beta_redeem,
                    LabelledStatement {
                        label: b"R_beta_redeem_alice",
                        statement: Statement::Schnorr {
                            g,
                            gx: points.R_beta_redeem,
                        },
                    },
                ),
                (
                    responses.R_beta_refund,
                    LabelledStatement {
                        label: b"R_beta_refund_alice",
                        statement: Statement::Schnorr {
                            g,
                            gx: points.R_beta_refund,
                        },
                    },
                ),
                (
                    responses.Y_R3,
                    LabelledStatement {
                        label: b"Y",
                        statement: Statement::DDH {
                            g,
                            gx: points.Y,
                            h: points.R_beta_redeem,
                            hx: points.R3,
                        },
                    },
                ),
            ],
        }
    }
}

impl From<Opening<CompactProof>> for CommitmentOpening {
    fn from(opening: Opening<CompactProof>) -> Self {
        let nonce = opening.nonce;
        let proof = opening.proof;

        let (X_beta, X_beta_response) = extract_schnorr!(proof, b"X_beta_bob");
        let (X_alpha, X_alpha_response) = extract_schnorr!(proof, b"X_alpha_bob");
        let (R_beta_redeem, R_beta_redeem_response) = extract_schnorr!(proof, b"R_beta_redeem_bob");
        let (R_beta_refund, R_beta_refund_response) = extract_schnorr!(proof, b"R_beta_refund_bob");

        CommitmentOpening {
            challenge: proof.challenge,
            nonce,
            points: BobPoints {
                X_beta,
                X_alpha,
                R_beta_redeem,
                R_beta_refund,
            },
            responses: BobResponses {
                X_beta: X_beta_response,
                X_alpha: X_alpha_response,
                R_beta_redeem: R_beta_redeem_response,
                R_beta_refund: R_beta_refund_response,
            },
        }
    }
}

impl From<CommitmentOpening> for Opening<CompactProof> {
    fn from(opening: CommitmentOpening) -> Self {
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

// Bob => Alice
pub struct KeyGenMsg1 {
    pub commitment: Commitment,
}

// Alice => Bob
pub struct KeyGenMsg2 {
    pub challenge: FE,
    pub points: AlicePoints,
    pub responses: AliceResponses,
}

// Bob => Alice
pub struct KeyGenMsg3 {
    pub commitment_opening: CommitmentOpening,
    pub N_and_c: party_two::PaillierPublic,
    pub paillier_range_proof: RangeProofNi,
    pub paillier_correct_key_proof: NICorrectKeyProof,
}

// Alice => Bob
pub type PdlMsg1 = party_two::PDLFirstMessage;
// Bob => Alice
pub type PdlMsg2 = party_one::PDLFirstMessage;
// Alice => Bob
pub type PdlMsg3 = party_two::PDLSecondMessage;
// Bob => Alice
pub type PdlMsg4 = party_one::PDLSecondMessage;

// Alice => Bob
pub struct SignMsg3 {
    pub c_beta_redeem_missing_y_and_bob_R: BigInt,
    pub c_beta_refund_missing_bob_R: BigInt,
}

// Bob => Alice
pub struct SignMsg4 {
    pub s_beta_redeem_missing_y: FE,
    pub s_beta_refund: FE,
}

// Alice => Blockchain
pub struct BlockchainMsg {
    pub signature: Signature,
}

pub struct Signature {
    pub Rx: BigInt,
    pub s: FE,
}

use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};
// These are actually be determined from the assets and joint public keys etc
#[inline]
pub fn beta_redeem_tx() -> secp256k1::Message {
    secp256k1::Message::from_slice(
        &bitcoin_hashes::sha256d::Hash::hash(b"Pay from joint output X to Alice 10 BTC")[..],
    )
    .unwrap()
}

#[inline]
pub fn beta_refund_tx() -> secp256k1::Message {
    secp256k1::Message::from_slice(
        &bitcoin_hashes::sha256d::Hash::hash(b"Pay from joint output X to Bob 10 BTC")[..],
    )
    .unwrap()
}
