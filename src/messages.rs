use crate::{
    commited_nizk::{Commitment, Opening},
    ecdsa::Signature,
    nizk_sigma::{CompactProof, LabelledStatement, Statement},
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

macro_rules! extract_point {
    ($statements:expr, $label:expr) => {
        match $statements
            .iter()
            .find(|statement| statement.label == $label)
            .unwrap()
            .statement
        {
            Statement::Schnorr { gx, .. } => gx,
            _ => panic!("only use for schnorr"),
        }
    };
}

impl AlicePoints {
    pub fn into_statements(self) -> Vec<LabelledStatement> {
        let g = GE::generator();
        vec![
            LabelledStatement {
                label: b"X_beta_alice",
                statement: Statement::Schnorr { g, gx: self.X_beta },
            },
            LabelledStatement {
                label: b"R_beta_redeem_alice",
                statement: Statement::Schnorr {
                    g,
                    gx: self.R_beta_redeem,
                },
            },
            LabelledStatement {
                label: b"R_beta_refund_alice",
                statement: Statement::Schnorr {
                    g,
                    gx: self.R_beta_refund,
                },
            },
            LabelledStatement {
                label: b"Y",
                statement: Statement::DDH {
                    g,
                    gx: self.Y,
                    h: self.R_beta_redeem,
                    hx: self.R3,
                },
            },
        ]
    }

    pub fn from_statements(statements: Vec<LabelledStatement>) -> Self {
        let (Y, R3) = match statements
            .iter()
            .find(|statement| statement.label == b"Y")
            .unwrap()
            .statement
        {
            Statement::DDH { gx, hx, .. } => (gx, hx),
            _ => unreachable!("R3 is a DDH proof"),
        };

        AlicePoints {
            X_beta: extract_point!(statements, b"X_beta_alice"),
            R_beta_redeem: extract_point!(statements, b"R_beta_redeem_alice"),
            R_beta_refund: extract_point!(statements, b"R_beta_refund_alice"),
            R3,
            Y,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AliceResponses {
    pub X_beta: FE,
    pub R_beta_redeem: FE,
    pub R_beta_refund: FE,
    pub Y_R3: FE,
}

impl AliceResponses {
    pub fn into_vec(self) -> Vec<FE> {
        vec![
            self.X_beta,
            self.R_beta_redeem,
            self.R_beta_refund,
            self.Y_R3,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct BobPoints {
    pub X_alpha: GE,
    pub X_beta: GE,
    pub R_beta_redeem: GE,
    pub R_beta_refund: GE,
}

impl BobPoints {
    pub fn into_statements(self) -> Vec<LabelledStatement> {
        let g = GE::generator();
        vec![
            LabelledStatement {
                label: b"X_alpha_bob",
                statement: Statement::Schnorr {
                    g,
                    gx: self.X_alpha,
                },
            },
            LabelledStatement {
                label: b"X_beta_bob",
                statement: Statement::Schnorr { g, gx: self.X_beta },
            },
            LabelledStatement {
                label: b"R_beta_redeem_bob",
                statement: Statement::Schnorr {
                    g,
                    gx: self.R_beta_redeem,
                },
            },
            LabelledStatement {
                label: b"R_beta_refund_bob",
                statement: Statement::Schnorr {
                    g,
                    gx: self.R_beta_refund,
                },
            },
        ]
    }

    pub fn from_statements(statements: Vec<LabelledStatement>) -> Self {
        BobPoints {
            X_alpha: extract_point!(statements, b"X_alpha"),
            X_beta: extract_point!(statements, b"X_beta"),
            R_beta_redeem: extract_point!(statements, b"R_beta_redeem"),
            R_beta_refund: extract_point!(statements, b"R_beta_refund"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BobResponses {
    pub X_alpha: FE,
    pub X_beta: FE,
    pub R_beta_redeem: FE,
    pub R_beta_refund: FE,
}

impl BobResponses {
    pub fn into_vec(self) -> Vec<FE> {
        vec![
            self.X_alpha,
            self.X_beta,
            self.R_beta_redeem,
            self.R_beta_refund,
        ]
    }
}

// Bob => Alice
pub struct KeyGenMsg1 {
    pub commitment: Commitment,
}

// Alice => Bob
pub struct KeyGenMsg2 {
    pub proof: CompactProof,
    pub points: AlicePoints,
}

// Bob => Alice
pub struct KeyGenMsg3 {
    pub commitment_opening: Opening<CompactProof>,
    pub points: BobPoints,
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
pub struct SignMsg1 {
    pub c_beta_redeem_missing_y_and_bob_R: BigInt,
    pub c_beta_refund_missing_bob_R: BigInt,
}

// Bob => Alice
pub struct SignMsg2 {
    pub s_beta_redeem_missing_y: FE,
}

// Alice => Blockchain
pub struct BlockchainMsg {
    pub sig_beta_redeem: Signature,
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
