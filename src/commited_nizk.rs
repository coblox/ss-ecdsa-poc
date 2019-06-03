use crate::nizk_sigma_proof::{GenRngFromWitness, Proof, Witness};
use merlin::Transcript;
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct Commitment {
    inner: [u8; 32],
    label: &'static [u8],
}

#[derive(Debug, Clone)]
pub struct Opening<P> {
    nonce: [u8; 32],
    proof: P,
}

pub struct Nonce([u8; 32]);

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

        (
            Commitment {
                inner: commitment,
                label,
            },
            Opening { nonce, proof },
        )
    };

    transcript.add_commitment(&commitment);

    (commitment, opening)
}

pub struct Opener {
    transcript: Transcript,
    commitment: Commitment,
}

impl Opener {
    pub fn open<P: Proof>(&self, opening: Opening<P>) -> Result<P, ()> {
        let mut transcript = self.transcript.clone();
        if !opening.proof.verify(&mut transcript, self.commitment.label) {
            return Err(());
        }

        transcript.add_commited_nizk_nonce(self.commitment.label, opening.nonce);

        let commitment = transcript.get_commitment();
        if commitment == self.commitment.inner {
            Ok(opening.proof)
        } else {
            Err(())
        }
    }
}

impl Commitment {
    pub fn receive(self, transcript: &mut Transcript) -> Opener {
        let commitment_transcript = transcript.clone();
        transcript.add_commitment(&self);

        Opener {
            transcript: commitment_transcript,
            commitment: self,
        }
    }
}

trait CommitedNizkTranscript {
    fn add_commitment(&mut self, commitment: &Commitment);
    fn add_commited_nizk_nonce(&mut self, label: &'static [u8], nonce: [u8; 32]);
    fn get_commitment(&mut self) -> [u8; 32];
}

impl CommitedNizkTranscript for Transcript {
    fn add_commitment(&mut self, commitment: &Commitment) {
        self.append_message(b"ss-ecdsa-poc/commitment/1.0", commitment.label);
        self.append_message(b"commitment", &commitment.inner);
    }

    fn add_commited_nizk_nonce(&mut self, label: &'static [u8], nonce: [u8; 32]) {
        // Add a domin separator to the transcript to indicate we are commiting to the
        // above proof
        self.append_message(b"ss-ecdsa-poc/commited-nizk/1.0", label);
        self.append_message(b"nonce", &nonce);
    }

    fn get_commitment(&mut self) -> [u8; 32] {
        // Commit to the transcript by hashing it i.e. get a "challenge"
        let mut commitment = [0u8; 32];
        self.challenge_bytes(b"commitment", &mut commitment[..]);
        commitment
    }
}
