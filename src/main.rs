use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    CurveGroup, Group,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;
use std::{fs::File, io::Read, ops::Mul};

use prompt::{puzzle, welcome};

#[derive(Debug)]
pub enum Error {
    InvalidMsg,
}

// Same as in Puzzle 2
fn hasher() -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    let wb_to_curve_hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(
            &[1, 3, 3, 7],
        )
        .unwrap();
    wb_to_curve_hasher
}

// ElGamal: First element is sender's public key, second is the ciphertext
// Note that the message is specific to a given receiver and their public key
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamal(G1Affine, G1Affine);

// Implement a hashing function G1 -> G2
impl ElGamal {
    pub fn hash_to_curve(&self) -> G2Affine {
        let mut data = Vec::new();
        self.serialize_uncompressed(&mut data).unwrap();

        hasher().hash(&data).unwrap()
    }
}

// Messages, G1
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Message(G1Affine);

// Sender of a message: Public key y in G1, Secret key x in field 12_381 (?) I think G2
struct Sender {
    pub sk: Fr,
    pub pk: G1Affine,
}

// Receiver of a message: Public key in G1
pub struct Receiver {
    pk: G1Affine,
}

// Auditor of a message
pub struct Auditor {}

impl Sender {
    // Send a message to a given receiver
    pub fn send(&self, m: Message, r: &Receiver) -> ElGamal {
        // Ciphertext = Receiver's public key * Sender's secret key + Message plain text
        let c_2: G1Affine = (r.pk.mul(&self.sk) + m.0).into_affine();

        // Make an instance of ElGamal with sender's public key, ciphertext
        ElGamal(self.pk, c_2)
    }

    // Authenticate a message sent to self
    // From this we learn signature = hash(ciphertext) * sk
    pub fn authenticate(&self, c: &ElGamal) -> G2Affine {
        let hash_c = c.hash_to_curve();
        // Hashed cipher text * My secret key
        hash_c.mul(&self.sk).into_affine()
    }
}

impl Auditor {
    // Check the authenticity of a tuple (sender_pk, ciphertext, signature)
    pub fn check_auth(sender_pk: G1Affine, c: &ElGamal, s: G2Affine) -> bool {
        let lhs = { Bls12_381::pairing(G1Projective::generator(), s) };

        // Hash the ciphertext
        let hash_c = c.hash_to_curve();
        let rhs = { Bls12_381::pairing(sender_pk, hash_c) };

        // G * signature == public_key * hashed_cipher
        lhs == rhs
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Blob {
    pub sender_pk: G1Affine,
    pub c: ElGamal,
    pub s: G2Affine,
    pub rec_pk: G1Affine,
}

/*
    Generate the set of all possible values a message can take before it is processed
    and encrypted and signed
    This method takes the list of all raw messages,
    multiplies by g1 to get a point on the curve,
    and returns that list
*/
fn generate_message_space() -> [Message; 10] {
    // Generator
    let g1 = G1Projective::generator();
    // Message data
    let msgs = [
        390183091831u64,
        4987238947234982,
        84327489279482,
        8492374892742,
        5894274824234,
        4982748927426,
        48248927348927427,
        489274982749828,
        99084321987189371,
        8427489729843712893,
    ];
    // Change raw message data into the Message structure 
    msgs.iter()
        // Multiply each by the generator
        .map(|&msg_i| Message(g1.mul(Fr::from(msg_i)).into_affine()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

// An alteration of the above check_auth used to check message equality
// e(pk', sig) == e(pk_agg, H(c))
pub fn check_message_match(c: &ElGamal, s: G2Affine, receiver_pk: G1Affine, message: Message) -> bool {
    let lhs = { Bls12_381::pairing(receiver_pk, s) };

    // From the below derivation, the aggregate public key is
    // pk_agg = receiver_pk * sender_pk = cipher.1 - message
    let pk_agg = (c.1 - message.0).into_affine();
    let hash_c = c.hash_to_curve();
    let rhs = { Bls12_381::pairing(pk_agg, hash_c) };

    // e(pk', sig) == e(pk * pk', H(c))
    lhs == rhs
}

pub fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let messages = generate_message_space();

    let mut file = File::open("blob.bin").unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let blob = Blob::deserialize_uncompressed(data.as_slice()).unwrap();

    // ensure that blob is correct
    assert!(Auditor::check_auth(blob.sender_pk, &blob.c, blob.s));

    /* Implement your attack here, to find the index of the encrypted message */

    for (i, message) in messages.iter().enumerate() {
        /*
        let sender = Sender{sk: DONT_KNOW, pk: blob.sender_pk};
        let receiver = Receiver{pk: blob.rec_pk};

        let el_gamal = sender.send(m, &receiver);

        DOES THE FOLLOWING
        let c_1: G1Affine = self.pk
        
        let c_2: G1Affine = (r.pk.mul(&self.sk) + m.0).into_affine();
        >>> c_2 = receiver_pk * sender_sk + message
        
        let msg_ciph = ElGamal(self.pk, c_2)
        
        let new_ciph = blob.c;

        These should be equal for the matching message, and:
        blob.c.1 - message
        = receiver_pk * sender_sk
        = G * receiver_sk * sender_sk
        = G * (receiver_sk * sender_sk)
        Which is the public key of
        pk_agg = receiver_pk * sender_pk

        We want to do authnetication with something like that
        check_auth(pk_agg, &blob.c, blob.s)
        e(G, sig) == e(pk_agg, H(cipher))
        sk * e(G, H(c)) == sk * sk' * e(G, H(c))
        
        But that isn't the check we want (Because of the extra sk')
        We want to relate sk' to something known (pk') and then form another pairing
        pk' = sk' * G

        e(pk', sig) == e(pk_agg, H(c))
        e(sk' * G, sig) == e(pk * pk', H(c))
        sk' * e(G, sig) == e(G * sk * sk', H(c))
        sk' * e(G, sig) == sk * sk' * e(G, H(c))
        sk' * e(G, sk * H(c)) == sk * sk' * e(G, H(c))
        sk * sk' * e(G, H(c)) == sk * sk' * e(G, H(c))

        Which is very similar to the check_auth function but with a pk' on the left instead of generator
        (And pk_agg on the right instead of pk)
        This allows us to check without knowing either of the secret keys

        */
        if check_message_match(&blob.c, blob.s, blob.rec_pk, *message) {
            println!("Index of encrypted message: {}", i);
        }
    }

    /* End of attack */
}

const PUZZLE_DESCRIPTION: &str = r"
Bob designed a new one time scheme, that's based on the tried and true method of encrypt + sign. He combined ElGamal encryption with BLS signatures in a clever way, such that you use pairings to verify the encrypted message was not tampered with. Alice, then, figured out a way to reveal the plaintexts...
";
