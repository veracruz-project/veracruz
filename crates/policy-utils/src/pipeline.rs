use std::fmt::Debug;
use std::vec::Vec;

#[derive(Debug, Clone)]
pub enum Expr {
    Literal(String),
    Seq(Vec<Box<Expr>>),
    IfElse(String, Box<Expr>, Option<Box<Expr>>),
}
