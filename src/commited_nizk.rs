use crate::nizk_sigma_proof::{GenRngFromWitness, Proof, Witness};
use merlin::Transcript;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct Commitment([u8; 32]);

#[derive(Debug, Clone)]
pub struct Opening<P> {
    pub nonce: [u8; 32],
    pub proof: P,
}

pub fn commit_nizk<P: Proof>(
    transcript: &mut Transcript,
    label: &'static [u8],
    witness: &[Witness],
) -> (Commitment, Opening<P>) {
    let (commitment, opening) = {
        // This is our secret transcript for the proof that will be committed to.
        let mut transcript = transcript.clone();
        let proof = Proof::prove(&mut transcript, label, witness);

        // Add a random nonce to the transcript to act as the blinding factor in the
        // commitment ie H(x,r)
        let mut transcript_rng = transcript.gen_rng_from_witness(witness);
        let mut nonce = [0u8; 32];
        transcript_rng.fill_bytes(&mut nonce);

        transcript.add_commited_nizk_nonce(label, nonce);

        let commitment = transcript.get_commitment();

        (Commitment(commitment), Opening { nonce, proof })
    };

    transcript.add_commitment(label, &commitment);

    (commitment, opening)
}

#[derive(Clone)]
pub struct Opener {
    transcript: Transcript,
    commitment: Commitment,
    label: &'static [u8],
}

impl Opener {
    pub fn open<P: Proof>(&self, opening: Opening<P>) -> Result<P, ()> {
        let mut transcript = self.transcript.clone();
        if !opening.proof.verify(&mut transcript, self.label) {
            return Err(());
        }

        transcript.add_commited_nizk_nonce(self.label, opening.nonce);

        let commitment = transcript.get_commitment();
        if commitment == self.commitment.0 {
            Ok(opening.proof)
        } else {
            Err(())
        }
    }
}

impl Commitment {
    pub fn receive(self, transcript: &mut Transcript, label: &'static [u8]) -> Opener {
        let commitment_transcript = transcript.clone();
        transcript.add_commitment(label, &self);

        Opener {
            transcript: commitment_transcript,
            commitment: self,
            label,
        }
    }
}

trait CommitedNizkTranscript {
    fn add_commitment(&mut self, label: &'static [u8], commitment: &Commitment);
    fn add_commited_nizk_nonce(&mut self, label: &'static [u8], nonce: [u8; 32]);
    fn get_commitment(&mut self) -> [u8; 32];
}

impl CommitedNizkTranscript for Transcript {
    fn add_commitment(&mut self, label: &'static [u8], commitment: &Commitment) {
        self.append_message(b"ss-ecdsa-poc/commited-nizk/commitment/1.0", label);
        self.append_message(b"commitment", &commitment.0);
    }

    fn add_commited_nizk_nonce(&mut self, label: &'static [u8], nonce: [u8; 32]) {
        // Add a domin separator to the transcript to indicate we are commiting to the
        // above proof
        self.append_message(b"ss-ecdsa-poc/commited-nizk/commited-transcript/1.0", label);
        self.append_message(b"nonce", &nonce);
    }

    fn get_commitment(&mut self) -> [u8; 32] {
        // Commit to the transcript by hashing it i.e. get a "challenge"
        let mut commitment = [0u8; 32];
        self.challenge_bytes(b"commitment", &mut commitment[..]);
        commitment
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::nizk_sigma_proof::{CompactProof, StatementKind};
    use curv::{
        elliptic::curves::traits::{ECPoint, ECScalar},
        FE, GE,
    };

    #[test]
    fn test() {
        let x1 = FE::new_random();
        let x2 = FE::new_random();
        let g = GE::generator();
        let h = GE::base_point2();

        let mut transcript_prover = Transcript::new(b"commit_test");
        let mut transcript_verifier = Transcript::new(b"commit_test");

        let witness = vec![
            Witness {
                x: x1,
                kind: StatementKind::Schnorr { g },
                label: b"x1",
            },
            Witness {
                x: x2,
                kind: StatementKind::DDH { g, h },
                label: b"x2",
            },
        ];

        let (commitment, opening) =
            commit_nizk::<CompactProof>(&mut transcript_prover, b"proof_name", &witness);

        let opener = commitment.receive(&mut transcript_verifier, b"proof_name");
        // HACK: use this get commitment thing to test that the prover and verifier are
        // in the same state afterwards
        assert_eq!(
            transcript_prover.get_commitment(),
            transcript_verifier.get_commitment()
        );
        assert!(opener.open(opening).is_ok());
    }
}
