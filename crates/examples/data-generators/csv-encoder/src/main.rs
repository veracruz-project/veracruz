//! csv-encoder
//!
//! # Purpose
//!
//! This utility is designed to parse comma separated value (CSV) files,
//! converting the text representation of CSV file entries into numerical or
//! other data types (such as 32-bit integers), per a schema, and then output
//! selected columns of the converted CSV file into a uniform binary
//! representation encoded with `postcard`.
//!
//! This is useful for moving data into a Veracruz enclave (for use in e.g.
//! privacy-preserving machine learning) in a form more convenient than CSV.
//!
//! # Command line parameters
//!
//! Required command line parameters:
//!
//!     - *input* provides a path to a CSV file on disk.
//!     - *output* provides a path to a binary encoding of the CSV file encoded
//!       with `postcard`, per a schema.
//!     - *schema* provides a path to a TOML schema file on disk describing how
//!       the input CSV file should be encoded to produce the binary output of
//!       this utility.
//!
//! # The CSV schema file
//!
//! The TOML schema file has the following fields:
//!
//!     - *delimiter* a `u8` value (ASCII char) describing the input CSV file's
//!       delimiting character, which separates columns.  If no field is
//!       provided this defaults to ',' (a "comma").
//!     - *quote* a `u8` value (ASCII char) describing the input CSV file's
//!       quote character, which surrounds column entries.  If no field is
//!       provided this defaults to '"' (a "double quote").
//!     - *has-headers* a Boolean value describing whether the first row of the
//!       CSV file should be ignored as column titles or not.  If no field is
//!       provided this defaults to `false`.
//!     - *trim-whitespace* a Boolean value describing whether whitespace should
//!       be trimmed from column entries or not.  If no field is provided this
//!       defaults to `false`.
//!     - *flexible* a Boolean value indicating whether rows with missing
//!       trailing entries are cut short, or continue with empty entries.  If no
//!       field is provided this defaults to `false`.
//!     - *skip-rows-on-decoding-error* a Boolean value indicating that rows in
//!       the input CSV file that fail to parse should be skipped in the output.
//!       If no field is provided this defaults to `false`.
//!     - *columns* a mandatory array value of encoding descriptors, indicating
//!       how the column should be encoded in the output binary file.  Possible
//!       descriptors are:
//!         - *discard*: the contents of this column should not appear in the
//!           output binary file.
//!         - *f64*: the contents of this column are 64-bit floats and should be
//!           encoded as such in the output binary file.
//!         - *f32*: the contents of this column are 32-bit floats and should be
//!           encoded as such in the output binary file.
//!         - *u64*: the contents of this column are 64-bit unsigned integers
//!           and should be encoded as such in the output binary file.
//!         - *u32*: the contents of this column are 32-bit unsigned integers
//!           and should be encoded as such in the output binary file.
//!         - *i64*: the contents of this column are 64-bit signed integers and
//!           should be encoded as such in the output binary file.
//!         - *i32*: the contents of this column are 32-bit signed integers and
//!           should be encoded as such in the output binary file.
//!         - *string*: the contents of this column are UTF-8/ASCII strings and
//!           should be encoded as such in the output binary file.
//!
//! Note that this utility will fail with a runtime error if the *columns* field
//! of the TOML schema file does not have an encoding entry for each column in
//! the input CSV file.
//!
//! # Output binaries
//!
//! Output binaries are encoded with `postcard` as a vector of vectors of
//! vectors of `u8` values.  That is: as a vector of rows with each entry in a
//! row of the CSV file either dropped or encoded as vectors of Little Endian
//! bytes for numerical types, or as the byte representation of a UTF-8 string
//! for string types, depending on the schema.  If a particular entry in the CSV
//! file cannot be encoded, then the utility will abort with no output file
//! written.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{
    boxed::Box, convert::TryFrom, error::Error, fs::File, io::prelude::*, process::exit,
    str::FromStr,
};

use clap::Arg;
use log::*;
use toml::*;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

const APPLICATION_NAME: &str = "csv-encoder";
const AUTHORS: &str = "The Veracruz Development Team.";
const VERSION: &str = "0.2.0";
const ABOUT: &str = "csv-encoder: encodes selected columns of a CSV file using postcard.";

////////////////////////////////////////////////////////////////////////////////
// Command-line parsing.
////////////////////////////////////////////////////////////////////////////////

/// Details how the contents of a CSV column should be encoded.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Encoding {
    /// Discard the column, do not encode it in the output.
    Discard,
    /// Encode the contents as a series of `f64` values.
    F64,
    /// Encode the contents as a series of `f32` values.
    F32,
    /// Encode the contents as a series of `i64` values.
    I64,
    /// Encode the contents as a series of `i32` values.
    I32,
    /// Encode the contents as a series of `u64` values.
    U64,
    /// Encode the contents as a series of `u32` values.
    U32,
    /// Encode the contents as a UTF-8 `String` value.
    String,
}

/// Enables parsing of `Encoding` values with the `str::parse()` function.
impl FromStr for Encoding {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "discard" {
            Ok(Encoding::Discard)
        } else if value == "f64" || value == "F64" {
            Ok(Encoding::F64)
        } else if value == "f32" || value == "F32" {
            Ok(Encoding::F32)
        } else if value == "i64" || value == "I64" {
            Ok(Encoding::I64)
        } else if value == "i32" || value == "I32" {
            Ok(Encoding::I32)
        } else if value == "u32" || value == "U32" {
            Ok(Encoding::U32)
        } else if value == "u64" || value == "U64" {
            Ok(Encoding::U64)
        } else if value == "string" || value == "String" {
            Ok(Encoding::String)
        } else {
            Err(())
        }
    }
}

/// The global configuration for the conversion utility, capturing input and
/// output filenames, and information about which CSV columns to keep and how
/// their contents should be encoded.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandLineConfiguration {
    /// The source filename of the CSV file to parse.
    source_filename: String,
    /// The output filename of the encoded data.
    output_filename: String,
    /// The filename of the CSV schema descriptor.
    schema_filename: String,
}

impl CommandLineConfiguration {
    /// Creates a new configuration.
    #[inline]
    pub fn new() -> CommandLineConfiguration {
        CommandLineConfiguration {
            source_filename: String::new(),
            output_filename: String::new(),
            schema_filename: String::new(),
        }
    }

    /// Sets the source filename of the command line configuration.
    #[inline]
    pub fn set_source_filename(&mut self, file: String) -> &mut Self {
        self.source_filename = file;
        self
    }

    /// Sets the output filename of the command line configuration.
    #[inline]
    pub fn set_output_filename(&mut self, file: String) -> &mut Self {
        self.output_filename = file;
        self
    }

    /// Sets the schema filename of the command line configuration.
    #[inline]
    pub fn set_schema_filename(&mut self, file: String) -> &mut Self {
        self.schema_filename = file;
        self
    }

    /// Gets the input filename of the command line configuration.
    #[inline]
    pub fn get_input_filename(&self) -> &String {
        &self.source_filename
    }

    /// Gets the output filename of the command line configuration.
    #[inline]
    pub fn get_output_filename(&self) -> &String {
        &self.output_filename
    }

    /// Gets the schema filename of the command line configuration.
    #[inline]
    pub fn get_schema_filename(&self) -> &String {
        &self.schema_filename
    }
}

/// Parses the program's command line options, producing a command line
/// configuration object describing the program configuration.  Aborts the
/// program if parsing fails.
fn parse_command_line() -> CommandLineConfiguration {
    info!("Reading command line parameters.");

    let matches = clap::Command::new(APPLICATION_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(ABOUT)
        .arg(
            Arg::new("input")
                .short('i')
                .long("input")
                .value_name("FILE")
                .help("Name of input CSV file stored on disk.")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Name of encoded file to be stored on disk.")
                .required(true),
        )
        .arg(
            Arg::new("schema")
                .short('s')
                .long("schema")
                .value_name("FILE")
                .help("Name of TOML schema describing CSV file, and how it should be encoded.")
                .required(true),
        )
        .get_matches();

    let mut config = CommandLineConfiguration::new();

    if let Some(infile) = matches.get_one::<String>("input") {
        config.set_source_filename(infile.to_string());
    } else {
        eprintln!("No source filename provided.");
        exit(-1)
    }

    if let Some(outfile) = matches.get_one::<String>("output") {
        config.set_output_filename(outfile.to_string());
    } else {
        eprintln!("No target filename provided.");
        exit(-1)
    }

    if let Some(schema) = matches.get_one::<String>("schema") {
        config.set_schema_filename(schema.to_string());
    } else {
        eprintln!("No CSV schema filename provided.");
        exit(-1)
    }

    config
}

////////////////////////////////////////////////////////////////////////////////
// CSV schemas.
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Eq, PartialEq)]
/// A schema descriptor for the input CSV file, and a description of the encoded
/// output.
struct Schema {
    /// The CSV delimiting character.
    delimiter: u8,
    /// The CSV quote character.
    quote: u8,
    /// Whether the first row of the CSV file should be ignored as column titles
    /// or similar.
    has_headers: bool,
    /// Whether whitespace is present in the columns and should be trimmed, or
    /// not.
    trim_whitespace: bool,
    /// Whether empty entries are present, or not.
    flexible: bool,
    /// Whether CSV rows that fail to parse should be skipped in the output.
    skip_rows_on_decoding_error: bool,
    /// The description of how each column should be encoded in the output file.
    columns: Vec<Encoding>,
}

/// Reads a `u8` value from a field of a TOML value.  Returns `None` iff the
/// TOML value has no such field, or if the field exists but could not be
/// converted to a `u8` value.
#[inline]
fn read_u8(value: &Value, field: &str) -> Option<u8> {
    info!("Reading TOML field '{}'.", field);

    value
        .get(field)
        .and_then(|d| d.as_integer())
        .and_then(|s| u8::try_from(s).ok())
}

/// Reads a `bool` value from a field of a TOML value.  Returns `None` iff the
/// TOML value has no such field, or if the field exists but could not be
/// converted to a `bool` value.
#[inline]
fn read_bool(value: &Value, field: &str) -> Option<bool> {
    info!("Reading TOML field '{}'.", field);

    value.get(field).and_then(|d| d.as_bool())
}

/// Reads an array of `Encoding` values from a field of a TOML value. Returns
/// `None` iff the TOML value has no such field, or if the field exists but
/// could not be converted to a `Vec<Encoding>` value.
fn read_encoding_array(value: &Value, field: &str) -> Option<Vec<Encoding>> {
    info!("Reading TOML field '{}'.", field);

    let array = value.get(field).and_then(|d| d.as_array())?;
    let mut result = Vec::new();

    for entry in array {
        let entry = entry.as_str()?.parse::<Encoding>().ok()?;
        result.push(entry)
    }

    Some(result)
}

impl Schema {
    /// Creates a new empty schema with dummy delimiter and quote character, all
    /// Boolean flags set to `false`, and an empty list of column encodings.
    #[inline]
    pub fn new() -> Self {
        Schema {
            delimiter: 0,
            quote: 0,
            has_headers: false,
            trim_whitespace: false,
            flexible: false,
            skip_rows_on_decoding_error: true,
            columns: Vec::new(),
        }
    }

    /// Sets the schema's delimiting character.
    #[inline]
    pub fn set_delimiter(&mut self, delimiter: u8) -> &mut Self {
        self.delimiter = delimiter;
        self
    }

    /// Gets the schema's delimiting character.
    #[inline]
    pub fn get_delimiter(&self) -> u8 {
        self.delimiter
    }

    /// Sets the schema's quote character.
    #[inline]
    pub fn set_quote(&mut self, quote: u8) -> &mut Self {
        self.quote = quote;
        self
    }

    /// Gets the schema's quote character.
    #[inline]
    pub fn get_quote(&self) -> u8 {
        self.quote
    }

    /// Sets the schema's flag indicating that the CSV file has headers.
    #[inline]
    pub fn set_has_headers(&mut self, has_headers: bool) -> &mut Self {
        self.has_headers = has_headers;
        self
    }

    /// Gets the schema's flag indicating that the CSV file has headers.
    #[inline]
    pub fn get_has_headers(&self) -> bool {
        self.has_headers
    }

    /// Sets the schema's flag indicating that the CSV file has trimmable
    /// whitespace.
    #[inline]
    pub fn set_trim_whitespace(&mut self, trim_whitespace: bool) -> &mut Self {
        self.trim_whitespace = trim_whitespace;
        self
    }

    /// Gets the schema's flag indicating that the CSV file has trimmable
    /// whitespace.
    #[inline]
    pub fn get_trim_whitespace(&self) -> bool {
        self.trim_whitespace
    }

    /// Sets the schema's flag indicating that the CSV file has flexible rows of
    /// entries.
    #[inline]
    pub fn set_flexible(&mut self, flexible: bool) -> &mut Self {
        self.flexible = flexible;
        self
    }

    /// Gets the schema's flag indicating that the CSV file has flexible rows of
    /// entries.
    #[inline]
    pub fn get_flexible(&self) -> bool {
        self.flexible
    }

    /// Sets the schema's flag indicating that rows in the input CSV file that
    /// fail to parse should be suppressed in the output and not cause a runtime
    /// error.
    #[inline]
    pub fn set_skip_rows_on_decoding_error(&mut self, skip_rows: bool) -> &mut Self {
        self.skip_rows_on_decoding_error = skip_rows;
        self
    }

    /// Gets the schema's flag indicating that rows in the input CSV file that
    /// fail to parse should be suppressed in the output and not cause a runtime
    /// error.
    #[inline]
    pub fn get_skip_rows_on_decoding_error(&self) -> bool {
        self.skip_rows_on_decoding_error
    }

    /// Sets the schema's array of column encodings.
    #[inline]
    pub fn set_columns(&mut self, columns: Vec<Encoding>) -> &mut Self {
        self.columns = columns.to_vec();
        self
    }

    /// Gets the schema's array of column encodings.
    #[inline]
    pub fn get_columns(&self) -> &Vec<Encoding> {
        &self.columns
    }

    /// Reads a schema value from a TOML file stored on disk, at the filename
    /// `filename`.  Aborts the program if the file does not exist, or if it
    /// does not match the expected format (e.g. an optional key contains a
    /// value that cannot be parsed to a `u8` or `bool` value, or if the
    /// mandatory *columns* key is missing).  For missing optional keys, a
    /// default value is inserted into the schema instead.
    pub fn from_file(filename: &str) -> Schema {
        info!("Reading TOML schema file: '{}'.", filename);

        let mut contents = String::new();

        {
            let mut file = File::open(filename).unwrap_or_else(|err| {
                eprintln!(
                    "Cannot open CSV schema file '{}'.  Error '{}' returned.",
                    filename, err
                );
                exit(-1)
            });

            file.read_to_string(&mut contents).unwrap_or_else(|err| {
                eprintln!(
                    "Cannot read CSV schema file '{}'.  Error '{}' returned.",
                    filename, err
                );
                exit(-1)
            });
        }

        let toml: Value = from_str(&contents).unwrap_or_else(|err| {
            eprintln!(
                "Cannot parse TOML from file '{}'.  Error '{}' returned.",
                filename, err
            );
            exit(-1)
        });

        info!("Parsed TOML file.  Contents:");
        info!("{}", toml);

        let mut schema = Schema::new();

        if let Some(delimiter) = read_u8(&toml, "delimiter") {
            schema.set_delimiter(delimiter);
        } else {
            info!("TOML file contains no 'delimiter' key.  Using default.");
            schema.set_delimiter(b',');
        }

        if let Some(quote) = read_u8(&toml, "quote") {
            schema.set_quote(quote);
        } else {
            info!("TOML file contains no 'quote' key.  Using default.");
            schema.set_quote(b'"');
        }

        if let Some(has_headers) = read_bool(&toml, "has-headers") {
            schema.set_has_headers(has_headers);
        } else {
            info!("TOML file contains no 'has-headers' key.  Using default.");
            schema.set_has_headers(false);
        }

        if let Some(trim_whitespace) = read_bool(&toml, "trim-whitespace") {
            schema.set_trim_whitespace(trim_whitespace);
        } else {
            info!("TOML file contains no 'trim-whitespace' key.  Using default.");
            schema.set_trim_whitespace(false);
        }

        if let Some(flexible) = read_bool(&toml, "flexible") {
            schema.set_flexible(flexible);
        } else {
            info!("TOML file contains no 'flexible' key.  Using default.");
            schema.set_flexible(false);
        }

        if let Some(skip_rows) = read_bool(&toml, "skip-rows-on-decoding-error") {
            schema.set_skip_rows_on_decoding_error(skip_rows);
        } else {
            info!("TOML file contains no 'skip-rows-on-decoding-error' key.  Using default.");
            schema.set_skip_rows_on_decoding_error(false);
        }

        if let Some(columns) = read_encoding_array(&toml, "columns") {
            schema.set_columns(columns);
        } else {
            eprintln!(
                "TOML schema file '{}' missing mandatory 'columns' field.",
                filename
            );
            exit(-1)
        }

        schema
    }
}

/// Reads a CSV file from disk, as specified by the command line configuration,
/// in a format described by a schema.  Fails with `Err(error)`, where `error`
/// is an error message describing what went wrong, if the input CSV file does
/// not exist or if a row in the CSV file cannot be parsed.
fn read_csv(
    config: &CommandLineConfiguration,
    schema: &Schema,
) -> Result<Vec<csv::StringRecord>, Box<dyn Error>> {
    info!("Reading CSV file: '{}'.", config.get_input_filename());

    let trimming_mode = if schema.get_trim_whitespace() {
        csv::Trim::All
    } else {
        csv::Trim::None
    };

    let mut reader = csv::ReaderBuilder::new()
        .delimiter(schema.get_delimiter())
        .quote(schema.get_quote())
        .has_headers(schema.get_has_headers())
        .flexible(schema.get_flexible())
        .trim(trimming_mode)
        .from_path(config.get_input_filename())?;

    let mut buffer = Vec::new();

    for result in reader.records() {
        buffer.push(result?);
    }

    Ok(buffer)
}

////////////////////////////////////////////////////////////////////////////////
// Encoding columns.
////////////////////////////////////////////////////////////////////////////////

/// Encodes the input CSV file as a vector (rows) of vectors (column entries) of
/// vectors of Little Endian bytes (byte encoding of each row-column entry)
/// where the overall 3-dimensional vector is encoded with `postcard`.  Encodes
/// each row-column entry according to the schema provided.  If this encoding
/// does not fail, then opens up an output file, as specified by the command
/// line flags, and writes the output.  Aborts the program if any parsing or
/// encoding step fails, or if the file I/O fails.
fn encode_csv_content(
    config: &CommandLineConfiguration,
    schema: &Schema,
    rows: &[csv::StringRecord],
) {
    info!(
        "Encoding CSV content consisting of '{}' rows, aiming to write output file: '{}'.",
        rows.len(),
        config.get_output_filename()
    );

    /* Output, computed one row at a time */
    let mut encoding: Vec<Vec<Vec<u8>>> =
        vec![vec![Vec::new(); rows.len()]; schema.get_columns().len()];
    /* The current row being processed. */
    let mut current_row: Vec<Vec<u8>> = vec![Vec::new(); schema.get_columns().len()];
    /* The number of column entries that have been skipped. */
    let mut adjustment: usize = 0;
    /* Whether we skip any rows that have had an encoding error in an entry. */
    let skip_errors: bool = schema.get_skip_rows_on_decoding_error();
    /* Whether we've spotted an error in this row, so far. */
    let mut error: bool = false;
    /* The number of rows that did not have an encoding error. */
    let mut successful_row_count: usize = 0;

    for (row, row_entry) in rows.iter().enumerate() {
        for (column, column_entry) in row_entry.iter().enumerate() {
            if let Some(data_type) = schema.get_columns().get(column) {
                match data_type {
                    Encoding::Discard => {
                        adjustment += 1;
                    }
                    Encoding::String => {
                        current_row[column - adjustment] = column_entry.as_bytes().to_vec();
                    }
                    Encoding::I32 => {
                        match column_entry.parse::<i32>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                    Encoding::I64 => {
                        match column_entry.parse::<i64>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                    Encoding::U32 => {
                        match column_entry.parse::<u32>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                    Encoding::U64 => {
                        match column_entry.parse::<u64>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                    Encoding::F32 => {
                        match column_entry.parse::<f32>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                    Encoding::F64 => {
                        match column_entry.parse::<f64>() {
                            Ok(bytes) => {
                                current_row[column - adjustment] = bytes.to_le_bytes().to_vec();
                            }
                            Err(reason) => {
                                if skip_errors {
                                    info!("Error detected in row '{}'.  Row will be omitted from output.", row);
                                    error = true;
                                    adjustment += 1;
                                } else {
                                    eprintln!(
                                        "Encoding CSV entry '{}' failed with error: '{}'.",
                                        column_entry, reason
                                    );
                                    exit(-1);
                                }
                            }
                        }
                    }
                }
            } else {
                eprintln!(
                    "Schema TOML file does not describe encoding of column '{}' in CSV file '{}'.",
                    column,
                    config.get_input_filename()
                );
                exit(-1)
            }
        }
        if !error {
            successful_row_count += 1;
            current_row.shrink_to_fit();
            encoding.push(current_row.clone());
        } else {
            error = false;
        }
        adjustment = 0;
    }

    info!(
        "Writing output binary file consisting of '{}' successfully encoded rows.",
        successful_row_count
    );

    encoding.shrink_to_fit();

    match postcard::to_allocvec(&encoding) {
        Ok(bytes) => {
            if let Err(error) =
                File::create(config.get_output_filename()).and_then(|mut f| f.write_all(&bytes))
            {
                eprintln!(
                    "Writing target file '{}' failed with error: '{}'.",
                    config.get_output_filename(),
                    error
                );
                exit(-1)
            }
        }
        Err(error) => {
            eprintln!("Encoding with postcard failed with error: '{}'.", error);
            exit(-1)
        }
    }
}

/// Program entry point.  Reads the command line parameters, parses the TOML
/// schema file, then row-by-row encodes the CSV file as directed by the schema,
/// before dumping the `postcard` encoded file to the output file specified on
/// the command line.
fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let config = parse_command_line();
    let schema = Schema::from_file(config.get_schema_filename());
    let rows = read_csv(&config, &schema)?;

    encode_csv_content(&config, &schema, &rows);

    info!("Exiting program successfully.");

    Ok(())
}
