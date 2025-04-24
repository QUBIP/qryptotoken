use libcrux::kem::*;

fn main() {
    println!("Testing libcrux ml-kem");

    let mut rng = rand::rngs::OsRng;
    let (sk_a, pk_a) = key_gen(Algorithm::MlKem768, &mut rng).unwrap();
    let received_pk = pk_a.encode();

    let pk = PublicKey::decode(Algorithm::MlKem768, &received_pk).unwrap();
    let (ss_b, ct_b) = pk.encapsulate(&mut rng).unwrap();
    let received_ct = ct_b.encode();

    let ct_a = Ct::decode(Algorithm::MlKem768, &received_ct).unwrap();
    let ss_a = ct_a.decapsulate(&sk_a).unwrap();

    println!("{:?}", ss_b.encode());
    println!("{:?}", ss_a.encode());

    assert_eq!(ss_b.encode(), ss_a.encode());
}
