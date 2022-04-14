//! Huffman Encoding Example
//!
//! ## Context
//!
//! Reads user input, and then encodes the file to binary format to compress it and save space.
//! And then, it prints the encoded file.
//! After that, the encoded file gets converted back to the original text, and that is output too.
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

use std::fs ;
use anyhow::{self, Ok} ;

// For file input and output
const INPUT_FILENAME: &'static str = "/input/huffman_example_input.txt" ;
const OUTPUT_FILENAME: &'static str = "/output/encoded_output.txt" ;


// For the Algorithm
use std::collections::HashMap ;

type Link = Option<Box<Node>> ;

#[derive(Debug)]
struct Node {
    freq: i32,
    ch: Option<char>,
    
    left: Link,
    right: Link
}
    
fn new_node(freq: i32, ch: Option<char>) -> Node 
{
    Node {
        freq: freq,
        ch: ch,

        left: None,
        right: None,
    }
}

fn new_box(n: Node) -> Box<Node> 
{
    Box::new(n)
}

fn frequency(s: &str) -> HashMap<char, i32> 
{
    let mut hm = HashMap::new();
    for ch in s.chars() {
        let count = h.entry(ch).or_insert(0);
        *count += 1;  
    }

    hm
}
 
fn assign_codes(p: &Box<Node>, 
                hm: &mut HashMap<char, String>,
                s: String ) {

    if let Some(ch) = p.ch 
    {
        hm.insert(ch, s);
    }
    else 
    {
        if let Some(ref l) = p.left 
        {
            assign_codes(l, hm, s.clone() + "0") ;
        }
        if let Some(ref r) = p.right 
        {
            assign_codes(r, hm, s.clone() + "1") ;
        }
    }
}
 
fn encode_string(s: &str, hm: &HashMap<char, String>) -> String 
{
    let mut r = String::new() ;
    let mut t:Option<&String>;

    for ch in s.chars() {
        t = hm.get(&ch);
        r.push_str(t.unwrap());
    }

    r
}
 
fn decode_string(s: &str, root: &Box<Node>) -> String 
{

    let mut retval = "".to_string();
    let mut nodeptr = root;

    for x in s.chars() {
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
    
    // retval.pop();   // To remove \r\n from the end of the 'retval' String
    // retval.pop();

    // println!("{:?}", retval.as_str()) ;
    retval
}
            
fn main() -> anyhow::Result<()> 
{

    // Taking input of the file
    let file_vec = fs::read(INPUT_FILENAME)? ;

    let msg = String::from_utf8_lossy(&file_vec).to_string() ;
    let msg = msg.as_str() ;

    let hm = frequency(msg);

    let mut p:Vec<Box<Node>> = 
                      hm.iter()
                      .map(|x| new_box(new_node(*(x.1), Some(*(x.0)))))
                      .collect();

    while p.len() > 1 {
        p.sort_by(|a, b| (&(b.freq)).cmp(&(a.freq)));
        let a = p.pop().unwrap();
        let b = p.pop().unwrap();
        let mut c = new_box(new_node(a.freq + b.freq, None));
        c.left = Some(a);
        c.right = Some(b);
        p.push(c);
    }

    let root = p.pop().unwrap();
    let mut hm:HashMap<char, String> = HashMap::new();

    assign_codes(&root, &mut hm, "".to_string()); 

    // Storing the encoded and decoded strings, respectively
    let enc = encode_string(msg, &hm);
    let dec = decode_string(&enc, &root) ;

    let mut ret = String::new() ;

    ret.push_str("The encoded string is :-\n\n") ;
    ret.push_str(enc.as_str()) ;
    ret.push_str("\n\nThe decoded string is :-\n\n") ;
    ret.push_str(dec.as_str()) ;


    // Outputting the answer to the file
    fs::write(OUTPUT_FILENAME, ret)? ;

    Ok(())
}