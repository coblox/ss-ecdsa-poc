use curv::{cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof, BigInt, FE, GE};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi};

pub type KeyGenMsg1 = party_one::KeyGenFirstMsg;
pub type KeyGenMsg2 = party_two::KeyGenFirstMsg;

pub struct KeyGenMsg3 {
    pub commitment_opening: party_one::KeyGenSecondMsg,
    pub N_and_c: party_two::PaillierPublic,
    pub paillier_range_proof: RangeProofNi,
    pub paillier_correct_key_proof: NICorrectKeyProof,
}

pub type KeyGenMsg4 = party_two::PDLFirstMessage;
pub type KeyGenMsg5 = party_one::PDLFirstMessage;
pub type KeyGenMsg6 = party_two::PDLSecondMessage;
pub type KeyGenMsg7 = party_one::PDLSecondMessage;

pub type SignMsg1 = party_two::EphKeyGenFirstMsg;
pub type SignMsg2 = party_one::EphKeyGenFirstMsg;

pub struct SignMsg3 {
    pub commitment_opening: party_two::EphKeyGenSecondMsg,
    pub R3: GE,
    pub R3_DH_proof: ECDDHProof,
    pub c3: BigInt,
}

pub struct SignMsg4 {
    pub s_tag_tag: FE,
}

pub struct BlockchainMsg {
    pub signature: Signature,
}

pub struct Signature {
    pub Rx: BigInt,
    pub s: FE,
}
