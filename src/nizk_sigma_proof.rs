use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use merlin::{Transcript, TranscriptRng};
use rand::{thread_rng, RngCore};

#[derive(Debug, Clone)]
pub enum StatementKind {
    Schnorr { g: GE },
    DDH { g: GE, h: GE },
}

impl StatementKind {
    fn gen_commitment(&self, r: FE) -> Commitment {
        match self {
            StatementKind::Schnorr { g, .. } => {
                let gr = g * &r;
                Commitment::Schnorr { gr }
            }
            StatementKind::DDH { g, h, .. } => {
                let gr = g * &r;
                let hr = h * &r;
                Commitment::DDH { gr, hr }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Schnorr { g: GE, gx: GE },
    DDH { g: GE, gx: GE, h: GE, hx: GE },
}

impl Statement {
    fn recover_commitment(&self, minus_c: &FE, s: &FE) -> Commitment {
        match self {
            Statement::Schnorr { g, gx } => {
                let gr = (g * s) + (gx * minus_c);
                Commitment::Schnorr { gr }
            }
            Statement::DDH { g, gx, h, hx } => {
                let gr = (g * s) + (gx * minus_c);
                let hr = (h * s) + (hx * minus_c);
                Commitment::DDH { gr, hr }
            }
        }
    }
}

enum Commitment {
    Schnorr { gr: GE },
    DDH { gr: GE, hr: GE },
}

pub struct Witness {
    pub x: FE,
    pub kind: StatementKind,
    pub label: &'static [u8],
}

impl Witness {
    fn to_statement(&self) -> LabelledStatement {
        match self.kind {
            StatementKind::Schnorr { g } => {
                let gx = g * self.x;
                LabelledStatement {
                    label: self.label,
                    statement: Statement::Schnorr { g, gx },
                }
            }
            StatementKind::DDH { g, h } => {
                let gx = g * self.x;
                let hx = h * self.x;
                LabelledStatement {
                    label: self.label,
                    statement: Statement::DDH { g, gx, h, hx },
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LabelledStatement {
    pub label: &'static [u8],
    pub statement: Statement,
}

pub trait Proof {
    fn prove(transcript: &mut Transcript, label: &'static [u8], witnesses: &[Witness]) -> Self;
    fn verify(&self, transcript: &mut Transcript, label: &'static [u8]) -> bool;
}

#[derive(Debug, Clone)]
pub struct CompactProof {
    pub challenge: FE,
    pub responses: Vec<(FE, LabelledStatement)>,
}

impl CompactProof {
    pub fn get_response(&self, label: &'static [u8]) -> (FE, Statement) {
        let response = self
            .responses
            .iter()
            .find(|(_, labelled_statement)| labelled_statement.label == label)
            .expect("non-existent proof response");
        (response.0, response.1.statement.clone())
    }
}

impl Proof for CompactProof {
    fn prove(
        transcript: &mut Transcript,
        label: &'static [u8],
        witnesses: &[Witness],
    ) -> CompactProof {
        transcript.start_proof(label);

        let statements = witnesses
            .iter()
            .map(|w| {
                let statement = w.to_statement();
                transcript.add_statement(&statement);
                statement
            })
            .collect::<Vec<_>>();

        let commitments = produce_commitment(transcript, &witnesses);

        let c = transcript.get_challenge(b"chal");

        let response_scalars: Vec<FE> = witnesses
            .iter()
            .zip(commitments)
            .map(|(witness, (r, _))| r + c * witness.x)
            .collect();

        CompactProof {
            challenge: c,
            responses: response_scalars.into_iter().zip(statements).collect(),
        }
    }

    fn verify(&self, transcript: &mut Transcript, label: &'static [u8]) -> bool {
        transcript.start_proof(label);

        for (_, labelled_statement) in &self.responses {
            transcript.add_statement(&labelled_statement);
        }

        let minus_c = FE::zero().sub(&self.challenge.get_element());

        for (s, LabelledStatement { label, statement }) in &self.responses {
            let commitment = statement.recover_commitment(&minus_c, &s);
            transcript.add_commitment(label, &commitment);
        }

        let c = transcript.get_challenge(b"chal");
        self.challenge == c
    }
}

pub trait GenRngFromWitness {
    fn gen_rng_from_witness(&mut self, witnesses: &[Witness]) -> TranscriptRng;
}

impl GenRngFromWitness for Transcript {
    fn gen_rng_from_witness(&mut self, witnesses: &[Witness]) -> TranscriptRng {
        let mut rng_builder = self.build_rng();

        for witness in witnesses {
            rng_builder = rng_builder.rekey_with_witness_bytes(b"", &witness.x.get_element()[..]);
        }
        rng_builder.finalize(&mut thread_rng())
    }
}

// This could be re-used when doing a non-compact proof so I left it out here.
/// Given the witnesses generates a random "blidning factor", usually denoted as
/// r in the s = r + cx schnorr signature). Returns pairs of (r, R = g^r). We
/// call R the commitment.
fn produce_commitment(transcript: &mut Transcript, witnesses: &[Witness]) -> Vec<(FE, Commitment)> {
    let mut transcript_rng = transcript.gen_rng_from_witness(witnesses);

    witnesses
        .iter()
        .map(|witness| {
            let mut blinding = [0u8; 32];
            transcript_rng.fill_bytes(&mut blinding);
            let r: FE = ECScalar::from(&BigInt::from(&blinding[..]));
            let commitment = witness.kind.gen_commitment(r);
            transcript.add_commitment(witness.label, &commitment);
            (r, commitment)
        })
        .collect()
}

trait KeyGenTranscript {
    fn add_point(&mut self, label: &'static [u8], point: GE);
    fn start_proof(&mut self, label: &'static [u8]);
    fn add_commitment(&mut self, label: &'static [u8], commitment: &Commitment);
    fn add_statement(&mut self, statement: &LabelledStatement);
    fn get_challenge(&mut self, label: &'static [u8]) -> FE;
}

impl KeyGenTranscript for Transcript {
    fn add_point(&mut self, label: &'static [u8], point: GE) {
        self.append_message(label, &point.get_element().serialize()[..])
    }

    fn add_statement(&mut self, statement: &LabelledStatement) {
        match statement.statement {
            Statement::Schnorr { g, gx } => {
                self.append_message(b"sch", statement.label);
                self.add_point(b"g", g);
                self.add_point(b"gx", gx);
            }

            Statement::DDH { g, gx, h, hx } => {
                self.append_message(b"ddh", statement.label);
                self.add_point(b"g", g);
                self.add_point(b"gx", gx);
                self.add_point(b"h", h);
                self.add_point(b"hx", hx);
            }
        }
    }

    fn add_commitment(&mut self, label: &'static [u8], commitment: &Commitment) {
        match commitment {
            Commitment::Schnorr { gr } => {
                self.append_message(b"comm-sch", label);
                self.add_point(b"gr", *gr);
            }
            Commitment::DDH { gr, hr } => {
                self.append_message(b"comm-ddh", label);
                self.add_point(b"gr", *gr);
                self.add_point(b"hr", *hr);
            }
        }
    }

    fn start_proof(&mut self, label: &'static [u8]) {
        self.append_message(b"comit-nizk-sigma-proof/1.0", label);
    }

    fn get_challenge(&mut self, label: &'static [u8]) -> FE {
        let mut challenge = [0; 32];
        self.challenge_bytes(label, &mut challenge);
        ECScalar::from(&BigInt::from(&challenge[..]))
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn single_schnorr() {
        let x = FE::new_random();
        let g = GE::generator();
        let gx = g * x;
        let mut transcript_prover = Transcript::new(b"single_schnorr");
        let mut transcript_verifier = Transcript::new(b"single_schnorr");
        let witness = vec![Witness {
            x,
            kind: StatementKind::Schnorr { g },
            label: b"foo",
        }];
        let proof = CompactProof::prove(&mut transcript_prover, b"single_schnorr_proof", &witness);

        assert_eq!(
            proof.responses[0].1,
            LabelledStatement {
                label: b"foo",
                statement: Statement::Schnorr { g, gx },
            }
        );

        {
            let mut transcript_verifier = transcript_verifier.clone();
            let mut proof = proof.clone();
            proof.challenge = proof.challenge + FE::new_random();
            assert!(
                !proof.verify(&mut transcript_verifier, b"single_schnorr_proof"),
                "wrong challenge doesn't work"
            );
        }

        {
            let mut transcript_verifier = transcript_verifier.clone();
            assert!(
                !proof.verify(&mut transcript_verifier, b"single_derp_proof"),
                "should fail if wrong label is provided"
            );
        }

        {
            let mut transcript_verifier = transcript_verifier.clone();
            assert!(
                proof.verify(&mut transcript_verifier, b"single_schnorr_proof"),
                "correct label works"
            );
        }

        {
            let mut transcript_verifier = transcript_verifier.clone();
            assert!(
                proof.verify(&mut transcript_verifier, b"single_schnorr_proof"),
                "correct label works"
            );

            assert_eq!(
                transcript_verifier.get_challenge(b"test"),
                transcript_prover.get_challenge(b"test")
            );
        }
    }

    #[test]
    fn single_ddh() {
        let x = FE::new_random();
        let g = GE::generator();
        let h = GE::base_point2();
        let hx = h * x;
        let gx = g * x;
        let mut transcript_prover = Transcript::new(b"single_ddh");
        let mut transcript_verifier = Transcript::new(b"single_ddh");
        let witness = vec![Witness {
            x,
            kind: StatementKind::DDH { g, h },
            label: b"foo",
        }];
        let proof = CompactProof::prove(&mut transcript_prover, b"single_ddh_proof", &witness);

        assert_eq!(
            proof.responses[0].1,
            LabelledStatement {
                label: b"foo",
                statement: Statement::DDH { g, gx, h, hx },
            }
        );

        assert!(proof.verify(&mut transcript_verifier, b"single_ddh_proof"))
    }

    #[test]
    fn multiple() {
        let x1 = FE::new_random();
        let x2 = FE::new_random();
        let g = GE::generator();
        let h = GE::base_point2();

        let mut transcript_prover = Transcript::new(b"multiple");
        let mut transcript_verifier = Transcript::new(b"multiple");

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

        let proof = CompactProof::prove(&mut transcript_prover, b"multiple", &witness);

        {
            let mut proof = proof.clone();
            proof.responses.reverse();
            let mut transcript_verifier = transcript_verifier.clone();
            assert!(
                !proof.verify(&mut transcript_verifier, b"multiple"),
                "the order of the responses matters"
            );
        }

        {
            let mut transcript_verifier = transcript_verifier.clone();
            assert!(
                proof.verify(&mut transcript_verifier, b"multiple"),
                "doing multiple sigma proofs in parallel"
            );
        }
    }
}
