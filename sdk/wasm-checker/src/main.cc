//! WasmChecker
//!
//! Certifies that a WASM binary satisfies the Veracruz ABI.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#include <src/binary-reader-ir.h>
#include <src/result.h>
#include <src/option-parser.h>
#include <src/common.h>
#include <src/binary-reader.h>
#include <src/feature.h>
#include <src/stream.h>
#include <src/ir.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>

static std::string s_infile;
static std::string s_configfile = "wasm-checker-config.json";
static wabt::Features s_features;
static std::unique_ptr<wabt::FileStream> s_log_stream;
static bool s_read_debug_names = false;
static bool s_fail_on_custom_section_error = true;

static const char s_description[] =
R"(  Read a file in the WebAssembly binary format, and perform checks
  on it to decide if it complies with the Veracruz ABI rules.

examples:
  # parse binary file test.wasm
  $ wasm2wat test.wasm
)";

nlohmann::json config;

static void ParseOptions(int argc, char **argv) {
    wabt::OptionParser parser("wasm-checker", s_description);

    //s_log_stream = wabt::FileStream::CreateStdout();
    s_log_stream = NULL;

    parser.AddOption('c',
                     "configuration",
                     "I don't know what this is for",
                     "provide the json configuration file to be used for the run",
                     [](const char *argument) {
                         s_configfile = argument;
                         wabt::ConvertBackslashToSlash(&s_configfile);
                     });
                     
    parser.AddArgument("filename", wabt::OptionParser::ArgumentCount::One,
                       [](const char *argument) {
                           s_infile = argument;
                           wabt::ConvertBackslashToSlash(&s_infile);
                       });
    parser.Parse(argc, argv);

    std::ifstream i(s_configfile);
    i >> config;

    std::cout << "config.allowed_imports: " << config["allowed_imports"] << std::endl;
}
int main(int argc, char **argv) {
    wabt::Result result;

    ParseOptions(argc, argv);

    std::vector<uint8_t> file_data;

    std::cout << "wasm-checker reading file:" << s_infile << "\n";
    result = wabt::ReadFile(s_infile.c_str(), &file_data);
    if (wabt::Succeeded(result)) {
        wabt::Errors errors;
        wabt::Module module;
        wabt::ReadBinaryOptions options(s_features,
                                  s_log_stream.get(),
                                  s_read_debug_names,
                                  true,
                                  s_fail_on_custom_section_error);
        result = wabt::ReadBinaryIr(s_infile.c_str(),
                              file_data.data(),
                              file_data.size(),
                              options,
                              &errors,
                              &module);
        if (wabt::Succeeded(result)) {
            std::vector<wabt::Import *>::iterator this_import;
            for (this_import = module.imports.begin();
                 this_import != module.imports.end();
                 this_import++) {
                bool found = false;
                nlohmann::json::iterator this_allowed;
                for (this_allowed = config["allowed_imports"].begin(); this_allowed != config["allowed_imports"].end(); this_allowed++) {
                    if (*this_allowed == (*this_import)->field_name) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                     std::cout << "Import:" << (*this_import)->field_name << " forbidden" << std::endl;
                     result = wabt::Result::Error;
                 }
            }
        }
    }
    return (result != wabt::Result::Ok);
}
