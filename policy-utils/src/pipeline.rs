//! Simple pipelines of programs
//!
//! This module introduces the AST of a simple Bash-like scripting language for
//! sequencing tasks.  At present, the scripting language only consists of
//! program sequencing and conditional tests, though can grow over time.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use chumsky::prelude::*;
use std::{boxed::Box, collections::HashSet, iter::FromIterator, path::PathBuf};

/// Absolute/relative path separator token.
const PATH_SEPARATOR_TOKEN: &str = "/";

/// Pipeline sequencing operator token.
const PIPELINE_SEPARATOR_TOKEN: &str = ";";
/// Pipeline `if` token.
const PIPELINE_IF_TOKEN: &str = "if";
/// Pipeline `then` token.
const PIPELINE_THEN_TOKEN: &str = "then";
/// Pipeline `else` token.
const PIPELINE_ELSE_TOKEN: &str = "else";
/// Pipeline `end` token.
const PIPELINE_END_TOKEN: &str = "end";
/// Opening bracket token for pipelines.
const PIPELINE_OPEN_PARENTHESIS_TOKEN: &str = "(";
/// Closing bracket token for pipelines.
const PIPELINE_CLOSE_PARENTHESIS_TOKEN: &str = ")";
/// The universal success pipeline.
const PIPELINE_SUCCESS_TOKEN: &str = "success";
/// The universal failure pipeline.
const PIPELINE_ABORT_TOKEN: &str = "abort";

/// A pipeline of programs to execute in sequence, subject to conditional tests
/// on the return code of programs appearing in "test position".  Note that
/// executables return error codes: we take 0 as the success error code and
/// all other error codes as signalling failure.  For the purposes of these
/// pipelines, a success error code is essentially "truth" with a failure
/// error code representing "falsity".
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Pipeline {
    /// The abort pipeline, which unconditionally always fails, having no other
    /// side-effect.
    Abort,
    /// A single executable, represented by its filepath in the Veracruz VFS.
    /// The return code of the entire pipeline corresponds to the return code
    /// of the executable.  As explained above, executables are run within the
    /// context of a dynamic environment capturing program arguments and
    /// environment variable bindings.
    Executable {
        /// Path of the executable to execute.
        path: PathBuf,
        /// The arguments passed to the program.
        arguments: Vec<String>,
    },
    /// A sequence of pipelines, each executed in order.  If any pipeline within
    /// the sequence fails with a non-zero error code (or a runtime abort) then
    /// the entire pipeline fails with that same error code or a runtime abort.
    Sequence {
        /// The sequence of pipelines to execute.
        pipelines: Vec<Pipeline>,
    },
    /// A conditional check, permitting branching on the return code of a
    /// pipeline.
    Conditional {
        /// The "test" pipeline.  This is executed first, and if a success
        /// error code is returned the `andthen` pipeline is executed,
        /// otherwise the `orelse` pipeline is.  The return code of the
        /// entire pipeline is therefore taken from either the return code
        /// of `andthen` or `orelse`, and never from `test`.
        test: Box<Pipeline>,
        /// Pipeline executed in the "truth" case.
        andthen: Box<Pipeline>,
        /// Pipeline executed in the "falsity" case.
        orelse: Box<Pipeline>,
    },
}

impl Pipeline {
    /// Parses an absolute Unix-style path, of the form `/foo/goo/too`.  Returns
    /// `Ok(path)` if the parse was successful, and `path` was successfully
    /// extracted from the input string, otherwise returns `Err(e)` indicating
    /// a parse error.
    fn parse_absolute_path() -> impl Parser<char, PathBuf, Error = Simple<char>> {
        just("/")
            .ignore_then(text::ident().separated_by(just(PATH_SEPARATOR_TOKEN)))
            .map(|mut p| {
                p.insert(0, String::from("/"));
                PathBuf::from_iter(p)
            })
    }

    /// Parses the `success` pipeline.  Returns `Ok(pipeline)` if the parse was
    /// successful and `pipeline` was successfully extracted from the input
    /// string, otherwise returns `Err(e)` indicating a parse error.
    fn parse_success() -> impl Parser<char, Pipeline, Error = Simple<char>> {
        text::keyword(PIPELINE_SUCCESS_TOKEN).to(Self::success())
    }

    /// Parses the `abort` pipeline.  Returns `Ok(pipeline)` if the parse was
    /// successful and `pipeline` was successfully extracted from the input
    /// string, otherwise returns `Err(e)` indicating a parse error.
    fn parse_abort() -> impl Parser<char, Pipeline, Error = Simple<char>> {
        text::keyword(PIPELINE_ABORT_TOKEN).to(Self::abort())
    }

    /// Parses a pipeline.  Returns `Ok(pipeline)` if the parse was
    /// successful and `pipeline` was successfully extracted from the input
    /// string, otherwise returns `Err(e)` indicating a parse error.
    fn parse_pipeline() -> impl Parser<char, Pipeline, Error = Simple<char>> {
        recursive(|p: Recursive<char, Pipeline, Simple<char>>| {
            // Two-armed conditionals, if-then-else.
            let conditional = text::keyword(PIPELINE_IF_TOKEN)
                .ignore_then(
                    p.clone()
                        .padded()
                        .then_ignore(text::keyword(PIPELINE_THEN_TOKEN))
                        .then(p.clone().padded())
                        .then_ignore(text::keyword(PIPELINE_ELSE_TOKEN))
                        .then(p.clone().padded())
                        .then_ignore(text::keyword(PIPELINE_END_TOKEN)),
                )
                .map(|((test, andthen), orelse)| Self::conditional(test, andthen, orelse));

            // One-armed conditionals, if-then.
            let one_armed_conditional = text::keyword(PIPELINE_IF_TOKEN)
                .ignore_then(
                    p.clone()
                        .padded()
                        .then_ignore(text::keyword(PIPELINE_THEN_TOKEN))
                        .then(p.clone())
                        .then_ignore(text::keyword(PIPELINE_END_TOKEN)),
                )
                .map(|(test, andthen)| Self::ifthen(test, andthen));

            // NB: parse program arguments.  For the time being just use the empty
            // string as a fixed program argument for every program.
            let factor = choice((
                Self::parse_absolute_path().map(|p| Self::executable(p, Vec::new())),
                Self::parse_success(),
                Self::parse_abort(),
                p.padded().delimited_by(
                    just(PIPELINE_OPEN_PARENTHESIS_TOKEN),
                    just(PIPELINE_CLOSE_PARENTHESIS_TOKEN),
                ),
                conditional,
                one_armed_conditional,
            ));

            factor
                .separated_by(just(PIPELINE_SEPARATOR_TOKEN).padded())
                .map(Self::sequence)
        })
    }

    /// Parses a pipeline.  Returns `Some(pipeline)` if the parse was
    /// successful and `pipeline` was successfully extracted from the input
    /// string, otherwise returns `None` if there was a parse error.
    ///
    /// The current recursive grammar of pipelines is as follows (in a pseudo
    /// BNF format, where <X> indicates a non-terminal):
    ///
    /// ```verbatim
    /// <path-component> ::= <alpha-numeric>+
    ///
    /// <relative-path> ::= <path-component>
    ///                  |  <path-component> '/' <relative-path>
    ///
    /// <absolute-path> ::= '/' <relative-path>
    ///
    /// <pipeline> ::= 'success'
    ///             |  'abort'
    ///             |  <pipeline> ';' <pipeline>
    ///             |  <absolute-path>
    ///             |  '(' pipeline ')'
    ///             |  'if' pipeline 'then' pipeline 'else' pipelined 'end'
    ///             |  'if' pipeline 'then' pipeline 'end'
    /// ```
    ///
    /// The formal semantics of these pipelines are as follows:
    ///
    /// - `success` terminates successfully, immediately, with no other
    ///   side-effect returning a `0` error code.  Note that this is
    ///   semantically equivalent to the empty sequence of pipelines,
    /// - `abort` terminates unsuccessfully, immediately, with no other
    ///   side-effect returning a `1` error cdoe,
    /// - `p ; q` first executes pipeline `p`.  If a non-zero error code is
    ///   returned by the execution of this pipeline, this return code is taken
    ///   as the return code of the sequenced pipeline.  Otherwise, the pipeline
    ///   `q` is executed within the context of any side-effects made by `p`,
    ///   with the return code of `q` taken as the return code of the entire
    ///   pipeline.
    /// - `/foo/goo/too` is assumed to point-to an executable in the Veracruz
    ///   VFS.  If no such executable exists then the pipeline suffers a runtim
    ///   abort, otherwise the executable is invoked, with the return code of
    ///   the executable representing the return code of the pipeline.
    /// - `(p)` has the same semantics as `p`.
    /// - `if p then t else f end` first executes `p`.  If `p` returns a `0`
    ///   error code then the pipeline `t` is executed with the return code of
    ///   the entire pipeline being taken as the return code of `t`.  Otherwise,
    ///   the pipeline `f` is executed with the return code of `f` being the
    ///   return code of the entire pipeline.
    /// - `if p then t end` is semantically identical to the one-armed
    ///   conditional pipeline `if p then t else success end`.
    #[inline]
    pub fn parse<S>(input: S) -> Option<Self>
    where
        S: Into<String>,
    {
        Self::parse_pipeline().parse(input.into()).ok()
    }

    /// Returns `true` iff the `input` can be parsed into a `Pipeline` without
    /// syntactic errors.
    #[inline]
    pub fn parseable<S>(input: S) -> bool
    where
        S: Into<String>,
    {
        Self::parse(input).is_some()
    }

    /// Constructs a single-node pipeline, corresponding to a single executable
    /// from a path and its program arguments.
    #[inline]
    pub fn executable<P>(path: P, arguments: Vec<String>) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::Executable {
            path: path.into(),
            arguments,
        }
    }

    /// Constructs a sequence pipeline from a vector of other pipelines.
    /// Equivalent to `success()` if passed an empty vector of pipeline.
    #[inline]
    pub fn sequence(pipelines: Vec<Self>) -> Self {
        Self::Sequence { pipelines }
    }

    /// Constructs a conditional pipeline from a test pipeline, and a pair of
    /// continuation pipelines for the "true" and "false" cases.
    #[inline]
    pub fn conditional(test: Self, andthen: Self, orelse: Self) -> Self {
        Self::Conditional {
            test: Box::new(test),
            andthen: Box::new(andthen),
            orelse: Box::new(orelse),
        }
    }

    /// The "success" pipeline.
    #[inline]
    pub fn success() -> Self {
        Self::sequence(Vec::new())
    }

    /// The "abort" pipeline.
    #[inline]
    pub fn abort() -> Self {
        Self::Abort
    }

    /// A "one armed" conditional pipeline with a continuation that is executed
    /// upon success of the test.
    #[inline]
    pub fn ifthen(test: Self, andthen: Self) -> Self {
        Self::conditional(test, andthen, Self::success())
    }

    /// Computes the set of paths to executables mentioned in a given pipeline.
    pub fn executables(&self) -> HashSet<PathBuf> {
        let mut executables = HashSet::new();
        let mut work = vec![self.clone()];

        while let Some(next) = work.pop() {
            match next {
                Pipeline::Executable { path, .. } => {
                    executables.insert(path);
                }
                Pipeline::Abort => (),
                Pipeline::Sequence { mut pipelines } => {
                    work.append(&mut pipelines);
                }
                Pipeline::Conditional {
                    test,
                    andthen,
                    orelse,
                } => {
                    work.push(*test);
                    work.push(*andthen);
                    work.push(*orelse)
                }
            }
        }

        executables
    }
}
