use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use merlin::{Transcript, TranscriptRng};
use rand::{thread_rng, RngCore};

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

pub struct LabelledStatement {
    label: &'static [u8],
    statement: Statement,
}

pub trait Proof {
    fn prove(transcript: &mut Transcript, label: &'static [u8], witnesses: &[Witness]) -> Self;
    fn verify(&self, transcript: &mut Transcript, label: &'static [u8]) -> bool;
}

pub struct CompactProof {
    pub challenge: FE,
    pub responses: Vec<(FE, LabelledStatement)>,
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

trait KeyGenSchnorrTranscript {
    fn add_point(&mut self, label: &'static [u8], point: GE);
    fn start_proof(&mut self, label: &'static [u8]);
    fn add_commitment(&mut self, label: &'static [u8], commitment: &Commitment);
    fn add_statement(&mut self, statement: &LabelledStatement);
    fn get_challenge(&mut self, label: &'static [u8]) -> FE;
}

impl KeyGenSchnorrTranscript for Transcript {
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

    fn single_schnorr() {}
}
