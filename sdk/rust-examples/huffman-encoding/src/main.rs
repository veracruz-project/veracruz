//! Huffman Encoding Example
//!
//! ## Context
//!
//! Reads user input, and then encodes the file to binary format to compress it and save space.
//! And then, it prints the encoded file.
//! After that, the encoded file gets converted back to the original text, then that is outputted.
//! WARNING: Program is only desinged for ASCII characters, not UTF-8 encoding !!
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use anyhow::{self, Ok};
use std::{collections::HashMap, fs};

const INPUT_FILENAME: &'static str = "/input/huffman_example_input.txt";
const OUTPUT_FILENAME: &'static str = "/output/encoded_output.txt";

type Link = Option<Box<Node>>;

#[derive(Debug)]

/// A Binary Tree Node is represented here
struct Node {
    /// Each Node, must represent a character, and its frequency in the input string
    freq: i32,
    ch: Option<char>,

    /// The nodes for left and right children of the node
    left: Link,
    right: Link,
}

/// Function to create a new node, (ike a Constructor function)
#[inline]
fn new_node(freq: i32, ch: Option<char>) -> Node {
    Node {
        freq: freq,
        ch: ch,

        left: None,
        right: None,
    }
}

/// Count the frequency of occurence of each unique ASCII character in the input string
#[inline]
fn frequency(s: &str) -> HashMap<char, i32> {
    let mut hm = HashMap::new();
    for ch in s.chars() {
        let count = hm.entry(ch).or_insert(0);
        *count += 1;
    }

    hm
}

/// Assign the binary codes to each unique ASCII character in the input string
fn assign_codes(p: &Node, hm: &mut HashMap<char, String>, s: String) {
    if let Some(ch) = p.ch {
        hm.insert(ch, s);
    } else {
        if let Some(ref l) = p.left {
            assign_codes(l, hm, s.clone() + "0");
        }
        if let Some(ref r) = p.right {
            assign_codes(r, hm, s.clone() + "1");
        }
    }
}

/// Takes the huffman tree and input string, to return the encoded string
#[inline]
fn encode_string<A>(s: A, hm: &HashMap<char, String>) -> String
where
    A: AsRef<str>,
{
    let mut r = String::new();
    let mut t: Option<&String>;

    for ch in s.as_ref().chars() {
        t = hm.get(&ch);
        r.push_str(t.expect("couldn't push into the string 'r' inside 'encode_string()'"));
    }

    r
}

/// Takes the Huffman Tree and encoded string, to return the decoded string
#[inline]
fn decode_string<A>(s: A, root: &Node) -> String
where
    A: AsRef<str>,
{
    let mut retval = String::new();
    let mut nodeptr = root;

    for x in s.as_ref().chars() {
        if x == '0' {
            if let Some(ref l) = nodeptr.left {
                nodeptr = l;
            }
        } else {
            if let Some(ref r) = nodeptr.right {
                nodeptr = r;
            }
        }
        if let Some(ch) = nodeptr.ch {
            retval.push(ch);
            nodeptr = root;
        }
    }

    retval
}

fn main() -> anyhow::Result<()> {
    let file_vec = fs::read(INPUT_FILENAME)?;

    let msg = String::from_utf8_lossy(&file_vec).to_string();
    let msg = msg.as_str();

    let hm = frequency(msg);

    let mut p: Vec<Box<Node>> = hm
        .iter()
        .map(|x| Box::new(new_node(*(x.1), Some(*(x.0)))))
        .collect();

    while p.len() > 1 {
        p.sort_by(|a, b| (&(b.freq)).cmp(&(a.freq)));
        let a = p.pop().expect("error occured inside main while loop");
        let b = p.pop().expect("error occured inside main while loop");
        let mut c = Box::new(new_node(a.freq + b.freq, None));
        c.left = Some(a);
        c.right = Some(b);
        p.push(c);
    }

    let root = p
        .pop()
        .expect("error occured during building of binary tree using &Box<Node>");
    let mut hm: HashMap<char, String> = HashMap::new();

    assign_codes(&root, &mut hm, String::new());

    let enc = encode_string(msg, &hm);
    let dec = decode_string(&enc, &root);

    let mut ret = String::new();

    ret.push_str(enc.as_str());
    ret.push_str("\n\n");
    ret.push_str(dec.as_str());

    fs::write(OUTPUT_FILENAME, ret)?;

    Ok(())
}
