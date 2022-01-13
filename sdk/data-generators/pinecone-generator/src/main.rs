use std::fs;
use std::string::String;
use std::vec::Vec;
use pinecone::to_vec;
use serde::{Deserialize, Serialize};
use rand::Rng;

#[derive(Deserialize, Serialize, Clone, Debug)]
enum E1 {
    ENUM1(u32),
    ENUM2(i64),
    ENUM3(char),
    ENUM4(String),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T1 {
    f1: f64,
    f2: f64,
    f3: f64,
    i1: i64,
    i2: i64,
    i3: i64,
    c1: char,
    c2: char,
    c3: char,
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T2 {
    u1: u64,
    u2: u64,
    u3: u64,
    t1: T1,
    array1: [u16;7],
    array2: [i32;13],
    e1: E1,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
enum E2 {
    ENUM1(T2),
    ENUM2([u16;5]),
    ENUM3(u16),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct T3 {
    e1: E2,
    e2: E2,
    e3: E2,
}


fn main() {
    let mut rng = rand::thread_rng();
    let mut t3_array = Vec::new();
    for _ in 0..1_000_000 {
        t3_array.push(gen_t3(&mut rng));
    }

    fs::write("pinecone_string.dat", to_vec(&t3_array).unwrap()).unwrap();
}

fn gen_t3<T: Rng>(rng : &mut T) -> T3 {
    let t1 = T1 {
        f1: rng.gen(),
        f2: rng.gen(),
        f3: rng.gen(),
        i1: rng.gen(),
        i2: rng.gen(),
        i3: rng.gen(),
        c1: rng.gen(),
        c2: rng.gen(),
        c3: rng.gen(),
        e1: E1::ENUM4(String::from("hello rust")),
    };

    let t2 = T2 {
        u1: rng.gen(),
        u2: rng.gen(),
        u3: rng.gen(),
        t1: t1,
        array1: rng.gen(),
        array2: rng.gen(),
        e1: E1::ENUM2(rng.gen()),
    };

    T3 {
        e1: E2::ENUM1(t2),
        e2: E2::ENUM2(rng.gen()),
        e3: E2::ENUM3(rng.gen()),
    }
}
