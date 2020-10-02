//! Custom and derived functionality relating to Colima.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::colima;
#[cfg(feature = "sgx_attestation")]
use core::convert::TryInto;
use err_derive::Error;
use protobuf::{error::ProtobufError, Message, ProtobufEnum};
#[cfg(feature = "sgx_attestation")]
use sgx_types;
use std::{result::Result, string::ToString};

#[derive(Debug, Error)]
pub enum ColimaError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "Colima: ProtobufError: {:?}.", _0)]
    ProtobufError(#[error(source)] ProtobufError),
    #[error(display = "Colima: Invalid response status: {:?}.", _0)]
    ResponseStatusError(i32),
    #[error(display = "Colima: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
}
type ColimaResult = Result<std::vec::Vec<u8>, ColimaError>;

pub fn parse_mexico_city_request(buffer: &[u8]) -> Result<colima::MexicoCityRequest, ColimaError> {
    Ok(protobuf::parse_from_bytes::<colima::MexicoCityRequest>(
        buffer,
    )?)
}

pub fn parse_mexico_city_response(
    buffer: &[u8],
) -> Result<colima::MexicoCityResponse, ColimaError> {
    Ok(protobuf::parse_from_bytes::<colima::MexicoCityResponse>(
        buffer,
    )?)
}

pub fn parse_tabasco_request(buffer: &[u8]) -> Result<colima::TabascoRequest, ColimaError> {
    Ok(protobuf::parse_from_bytes::<colima::TabascoRequest>(
        buffer,
    )?)
}

pub fn parse_tabasco_response(buffer: &[u8]) -> Result<colima::TabascoResponse, ColimaError> {
    Ok(protobuf::parse_from_bytes::<colima::TabascoResponse>(
        buffer,
    )?)
}

#[cfg(feature = "sgx_attestation")]
fn parse_report_body(
    proto: &colima::SgxReportBody,
) -> Result<sgx_types::sgx_report_body_t, ColimaError> {
    let mut report_body = sgx_types::sgx_report_body_t::default();
    report_body.cpu_svn.svn.copy_from_slice(proto.get_cpu_svn());
    report_body.misc_select = proto.misc_select;
    report_body
        .isv_ext_prod_id
        .copy_from_slice(proto.get_isv_ext_prod_id());
    report_body.attributes = {
        sgx_types::sgx_attributes_t {
            flags: proto.get_attributes().get_flags(),
            xfrm: proto.get_attributes().get_xfrm(),
        }
    };
    report_body
        .mr_enclave
        .m
        .copy_from_slice(proto.get_mr_enclave());
    report_body
        .mr_signer
        .m
        .copy_from_slice(proto.get_mr_signer());
    report_body.config_id.copy_from_slice(proto.get_config_id());
    report_body.isv_prod_id = proto.get_isv_prod_id().try_into()?;
    report_body.config_svn = proto.get_config_svn().try_into()?;
    report_body
        .isv_family_id
        .copy_from_slice(proto.get_isv_family_id());
    report_body
        .report_data
        .d
        .copy_from_slice(proto.get_report_data());
    Ok(report_body)
}

#[cfg(feature = "sgx_attestation")]
fn parse_quote(proto: &colima::SgxQuote) -> Result<sgx_types::sgx_quote_t, ColimaError> {
    let mut quote = sgx_types::sgx_quote_t::default();
    quote.version = proto.get_version().try_into()?;
    quote.sign_type = proto.get_sign_type().try_into()?;
    quote
        .epid_group_id
        .copy_from_slice(proto.get_epid_group_id());
    quote.qe_svn = proto.get_qe_svn().try_into()?;
    quote.pce_svn = proto.get_pce_svn().try_into()?;
    quote.xeid = proto.get_xeid();
    quote.basename.name.copy_from_slice(proto.get_basename());
    quote.report_body = parse_report_body(proto.get_report_body())?;
    quote.signature_len = proto.get_signature_len();
    Ok(quote)
}

#[cfg(feature = "sgx_attestation")]
pub fn serialize_quote(quote: &sgx_types::sgx_quote_t) -> colima::SgxQuote {
    let mut result = colima::SgxQuote::default();
    result.version = quote.version.into();
    result.sign_type = quote.sign_type.into();
    result.epid_group_id.resize(quote.epid_group_id.len(), 0);
    result.epid_group_id.copy_from_slice(&quote.epid_group_id);
    result.qe_svn = quote.qe_svn.into();
    result.pce_svn = quote.pce_svn.into();
    result.xeid = quote.xeid;
    result.basename.resize(quote.basename.name.len(), 0);
    result.basename.copy_from_slice(&quote.basename.name);
    let report_body = {
        let mut ret = colima::SgxReportBody::default();
        ret.cpu_svn.resize(quote.report_body.cpu_svn.svn.len(), 0);
        ret.cpu_svn.copy_from_slice(&quote.report_body.cpu_svn.svn);
        ret.misc_select = quote.report_body.misc_select;
        ret.isv_ext_prod_id
            .resize(quote.report_body.isv_ext_prod_id.len(), 0);
        ret.isv_ext_prod_id
            .copy_from_slice(&quote.report_body.isv_ext_prod_id);
        let attributes = {
            let mut attributes = colima::SgxAttributes::default();
            attributes.flags = quote.report_body.attributes.flags;
            attributes.xfrm = quote.report_body.attributes.xfrm;

            attributes
        };
        ret.set_attributes(attributes);
        ret.mr_enclave
            .resize(quote.report_body.mr_enclave.m.len(), 0);
        ret.mr_enclave
            .copy_from_slice(&quote.report_body.mr_enclave.m);
        ret.mr_signer.resize(quote.report_body.mr_signer.m.len(), 0);
        ret.mr_signer
            .copy_from_slice(&quote.report_body.mr_signer.m);
        ret.config_id.resize(quote.report_body.config_id.len(), 0);
        ret.config_id.copy_from_slice(&quote.report_body.config_id);
        ret.isv_prod_id = quote.report_body.isv_prod_id.into();
        ret.isv_svn = quote.report_body.isv_svn.into();
        ret.config_svn = quote.report_body.config_svn.into();
        ret.isv_family_id
            .resize(quote.report_body.isv_family_id.len(), 0);
        ret.isv_family_id
            .copy_from_slice(&quote.report_body.isv_family_id);
        ret.report_data
            .resize(quote.report_body.report_data.d.len(), 0);
        ret.report_data
            .copy_from_slice(&quote.report_body.report_data.d);
        ret
    };
    result.set_report_body(report_body);
    result.signature_len = quote.signature_len;

    result
}

pub fn serialize_program(program_buffer: &[u8]) -> ColimaResult {
    let mut program = colima::Program::new();
    program.set_code(program_buffer.to_vec());
    let mut abs = colima::MexicoCityRequest::new();
    abs.set_program(program);

    Ok(abs.write_to_bytes()?)
}

pub fn serialize_program_data(data_buffer: &[u8], package_id: u32) -> ColimaResult {
    let mut data = colima::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_package_id(package_id);
    let mut colima = colima::MexicoCityRequest::new();
    colima.set_data(data);

    Ok(colima.write_to_bytes()?)
}

pub fn serialize_request_enclave_state() -> ColimaResult {
    let command = colima::RequestState::new();
    let mut request = colima::MexicoCityRequest::new();
    request.set_request_state(command);

    Ok(request.write_to_bytes()?)
}

pub fn serialize_stream(data_buffer: &[u8], package_id: u32) -> ColimaResult {
    let mut data = colima::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_package_id(package_id);
    let mut colima = colima::MexicoCityRequest::new();
    colima.set_stream(data);

    Ok(colima.write_to_bytes()?)
}

pub fn serialize_request_result() -> ColimaResult {
    let command = colima::RequestResult::new();
    let mut request = colima::MexicoCityRequest::new();
    request.set_request_result(command);

    Ok(request.write_to_bytes()?)
}

pub fn serialize_request_shutdown() -> ColimaResult {
    let command = colima::RequestShutdown::new();
    let mut request = colima::MexicoCityRequest::new();
    request.set_request_shutdown(command);

    Ok(request.write_to_bytes()?)
}

pub fn serialize_request_proxy_psa_attestation_token(challenge: &[u8]) -> ColimaResult {
    let mut rpat = colima::RequestProxyPsaAttestationToken::new();
    rpat.set_challenge(challenge.to_vec());
    let mut request = colima::MexicoCityRequest::new();
    request.set_request_proxy_psa_attestation_token(rpat);

    Ok(request.write_to_bytes()?)
}

pub fn serialize_request_next_round() -> ColimaResult {
    let command = colima::RequestNextRound::new();
    let mut request = colima::MexicoCityRequest::new();
    request.set_request_next_round(command);

    Ok(request.write_to_bytes()?)
}

pub fn parse_request_proxy_psa_attestation_token(
    proto: &colima::RequestProxyPsaAttestationToken,
) -> std::vec::Vec<u8> {
    proto.get_challenge().to_vec()
}

pub fn serialize_proxy_psa_attestation_token(
    token: &[u8],
    pubkey: &[u8],
    device_id: i32,
) -> ColimaResult {
    let mut pat_proto = colima::ProxyPsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_pubkey(pubkey.to_vec());
    pat_proto.set_device_id(device_id);
    let mut tabasco_request = colima::TabascoRequest::new();
    tabasco_request.set_proxy_psa_attestation_token(pat_proto);

    Ok(tabasco_request.write_to_bytes()?)
}

pub fn parse_proxy_psa_attestation_token(
    proto: &colima::ProxyPsaAttestationToken,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, i32) {
    (
        proto.get_token().to_vec(),
        proto.get_pubkey().to_vec(),
        proto.get_device_id(),
    )
}

pub fn serialize_native_psa_attestation_token(token: &[u8], device_id: i32) -> ColimaResult {
    let mut pat_proto = colima::NativePsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_device_id(device_id);
    let mut tabasco_request = colima::TabascoRequest::new();
    tabasco_request.set_native_psa_attestation_token(pat_proto);

    Ok(tabasco_request.write_to_bytes()?)
}

pub fn parse_native_psa_attestation_token(
    proto: &colima::NativePsaAttestationToken,
) -> (std::vec::Vec<u8>, i32) {
    (proto.get_token().to_vec(), proto.get_device_id())
}

pub fn parse_sgx_attestation_init(proto: &colima::SgxAttestationInit) -> (std::vec::Vec<u8>, i32) {
    (proto.get_public_key().to_vec(), proto.get_device_id())
}

pub fn serialize_sgx_attestation_init(pubkey: &[u8], device_id: i32) -> ColimaResult {
    let mut attest_init_proto = colima::SgxAttestationInit::new();
    attest_init_proto.set_public_key(pubkey.to_vec());
    attest_init_proto.set_device_id(device_id);
    let mut colima = colima::TabascoResponse::new();
    colima.set_sgx_attestation_init(attest_init_proto);

    Ok(colima.write_to_bytes()?)
}

#[cfg(feature = "sgx_attestation")]
pub fn parse_sgx_attestation_challenge(
    parsed: &colima::TabascoResponse,
) -> Result<
    (
        sgx_types::sgx_ra_context_t,
        sgx_types::sgx_ra_msg2_t,
        [u8; 16],
    ),
    ColimaError,
> {
    let context = parsed.get_context();
    let attestation_challenge = parsed.get_sgx_attestation_challenge();
    let challenge = {
        let chal = attestation_challenge.get_challenge();
        let mut value = [0; 16];
        value.copy_from_slice(chal);
        value
    };
    let msg2 = parse_msg2(&attestation_challenge.get_msg2())?;

    Ok((context, msg2, challenge))
}

#[cfg(feature = "sgx_attestation")]
pub fn serialize_sgx_attestation_challenge(
    context: sgx_types::sgx_ra_context_t,
    msg2: &sgx_types::sgx_ra_msg2_t,
    pubkey_challenge: &[u8],
) -> ColimaResult {
    let colima = {
        let attestation_challenge = {
            let msg2_proto = serialize_msg2(msg2);

            let mut attestation_challenge = colima::SgxAttestationChallenge::new();
            attestation_challenge
                .challenge
                .resize(pubkey_challenge.len(), 0);
            attestation_challenge
                .challenge
                .copy_from_slice(&pubkey_challenge);
            attestation_challenge.set_msg2(msg2_proto);

            attestation_challenge
        };

        let mut proto = colima::TabascoResponse::new();
        proto.set_sgx_attestation_challenge(attestation_challenge);
        proto.set_context(context);
        proto
    };

    Ok(colima.write_to_bytes()?)
}

pub fn serialize_psa_attestation_init(challenge: &[u8], device_id: i32) -> ColimaResult {
    let mut request = colima::TabascoResponse::new();
    let mut pai = colima::PsaAttestationInit::new();
    pai.set_challenge(challenge.to_vec());
    pai.set_device_id(device_id);
    request.set_psa_attestation_init(pai);
    Ok(request.write_to_bytes()?)
}

pub fn parse_psa_attestation_init(
    pai: &colima::PsaAttestationInit,
) -> Result<(std::vec::Vec<u8>, i32), ColimaError> {
    Ok((pai.get_challenge().to_vec(), pai.get_device_id()))
}

pub fn serialize_request_pi_hash() -> ColimaResult {
    let mut request = colima::MexicoCityRequest::new();
    let rph = colima::RequestPiHash::new();
    request.set_request_pi_hash(rph);
    Ok(request.write_to_bytes()?)
}

pub fn serialize_request_policy_hash() -> ColimaResult {
    let mut request = colima::MexicoCityRequest::new();
    let rph = colima::RequestPolicyHash::new();
    request.set_request_policy_hash(rph);
    Ok(request.write_to_bytes()?)
}

pub fn serialize_machine_state(machine_state: u8) -> ColimaResult {
    let mut response = colima::MexicoCityResponse::new();

    response.set_status(colima::ResponseStatus::SUCCESS);
    let mut state = colima::State::new();
    let slice = &vec![machine_state];

    state.state.resize(slice.len(), 0);
    state.state.copy_from_slice(slice);
    response.set_state(state);
    Ok(response.write_to_bytes()?)
}

pub fn serialize_pi_hash(hash: &[u8]) -> ColimaResult {
    let mut response = colima::MexicoCityResponse::new();

    response.set_status(colima::ResponseStatus::SUCCESS);
    let mut pi_hash = colima::PiHash::new();
    pi_hash.data.resize(hash.len(), 0);
    pi_hash.data.copy_from_slice(hash);
    response.set_pi_hash(pi_hash);
    Ok(response.write_to_bytes()?)
}

pub fn serialize_policy_hash(hash: &[u8]) -> ColimaResult {
    let mut response = colima::MexicoCityResponse::new();

    response.set_status(colima::ResponseStatus::SUCCESS);
    let mut policy_hash = colima::PolicyHash::new();
    policy_hash.data.resize(hash.len(), 0);
    policy_hash.data.copy_from_slice(hash);
    response.set_policy_hash(policy_hash);
    Ok(response.write_to_bytes()?)
}

pub fn serialize_empty_response(status: i32) -> ColimaResult {
    let mut response = colima::MexicoCityResponse::new();
    let encoded_status =
        colima::ResponseStatus::from_i32(status).ok_or(ColimaError::ResponseStatusError(status))?;
    response.set_status(encoded_status);

    Ok(response.write_to_bytes()?)
}

pub fn serialize_result(status: i32, data_opt: Option<std::vec::Vec<u8>>) -> ColimaResult {
    let mut response = colima::MexicoCityResponse::new();

    let encoded_status =
        colima::ResponseStatus::from_i32(status).ok_or(ColimaError::ResponseStatusError(status))?;

    response.set_status(encoded_status);

    if let Some(ref data) = data_opt {
        let mut result = colima::Result::new();
        result.data.resize(data.len(), 0);
        result.data.copy_from_slice(&data);
        response.set_result(result);
    }

    Ok(response.write_to_bytes()?)
}

pub fn parse_result(
    response: &colima::MexicoCityResponse,
) -> Result<Option<std::vec::Vec<u8>>, ColimaError> {
    let status = response.get_status();
    let decoded_status = match status {
        colima::ResponseStatus::UNSET => -1,
        colima::ResponseStatus::SUCCESS => 0,
        colima::ResponseStatus::FAILED_INVALID_ROLE => 1,
        colima::ResponseStatus::FAILED_NOT_READY => 2,
        colima::ResponseStatus::FAILED_GENERIC => 3,
        colima::ResponseStatus::FAILED_VM_ERROR => 4,
        colima::ResponseStatus::FAILED_ERROR_CODE_RETURNED => 5,
        colima::ResponseStatus::FAILED_INVALID_REQUEST => 6,
    };
    if status != colima::ResponseStatus::SUCCESS {
        return Err(ColimaError::ResponseStatusError(decoded_status));
    }

    let data_opt = {
        if response.has_result() {
            let result = response.get_result();
            let mut data = std::vec::Vec::new();
            data.resize(result.get_data().len(), 0);
            data.copy_from_slice(&response.get_result().data);
            Some(data)
        } else {
            None
        }
    };

    Ok(data_opt)
}

#[cfg(feature = "sgx_attestation")]
fn parse_msg3(abs: &colima::SgxAttestationTokens) -> (sgx_types::sgx_ra_msg3_t, i32) {
    let proto = abs.get_msg3();
    let device_id = proto.get_device_id();
    let mut msg3 = sgx_types::sgx_ra_msg3_t::default();
    msg3.mac.copy_from_slice(proto.get_mac());
    msg3.g_a.gx.copy_from_slice(proto.get_g_a().get_gx());
    msg3.g_a.gy.copy_from_slice(proto.get_g_a().get_gy());
    msg3.ps_sec_prop
        .sgx_ps_sec_prop_desc
        .copy_from_slice(proto.get_ps_sec_prop());
    (msg3, device_id)
}

#[cfg(feature = "sgx_attestation")]
pub fn parse_attestation_tokens(
    parsed: &colima::TabascoRequest,
) -> Result<
    (
        sgx_types::sgx_ra_msg3_t,
        sgx_types::sgx_quote_t,
        std::vec::Vec<u8>,
        sgx_types::sgx_quote_t,
        std::vec::Vec<u8>,
        i32,
    ),
    ColimaError,
> {
    let attest_tokens = parsed.get_sgx_attestation_tokens();
    let (msg3, device_id) = parse_msg3(attest_tokens);
    let msg3_quote = parse_quote(&attest_tokens.get_msg3_quote())?;
    let msg3_sig = {
        let proto = attest_tokens.get_msg3_sig();
        proto.to_vec()
    };
    let pubkey_quote = parse_quote(&attest_tokens.get_pubkey_quote())?;
    let pubkey_sig = {
        let sig = attest_tokens.get_pubkey_sig();
        sig.to_vec()
    };

    Ok((
        msg3,
        msg3_quote,
        msg3_sig,
        pubkey_quote,
        pubkey_sig,
        device_id,
    ))
}

#[cfg(feature = "sgx_attestation")]
pub fn serialize_sgx_attestation_tokens(
    context: sgx_types::sgx_ra_context_t,
    msg3: &sgx_types::sgx_ra_msg3_t,
    msg3_quote: &sgx_types::sgx_quote_t,
    msg3_sig: &std::vec::Vec<u8>,
    pubkey_quote: &sgx_types::sgx_quote_t,
    pubkey_sig: &std::vec::Vec<u8>,
    device_id: i32,
) -> ColimaResult {
    let msg3_proto = {
        let mut result = colima::SgxMsg3::new();
        result.set_device_id(device_id);
        result.mac.resize(msg3.mac.len(), 0);
        result.mac.copy_from_slice(&msg3.mac);
        let g_a = {
            let mut ret = colima::SgxEc256Public::default();
            ret.gx.resize(msg3.g_a.gx.len(), 0);
            ret.gx.copy_from_slice(&msg3.g_a.gx);
            ret.gy.resize(msg3.g_a.gy.len(), 0);
            ret.gy.copy_from_slice(&msg3.g_a.gy);
            ret
        };
        result.set_g_a(g_a);
        result
            .ps_sec_prop
            .resize(msg3.ps_sec_prop.sgx_ps_sec_prop_desc.len(), 0);
        result
            .ps_sec_prop
            .copy_from_slice(&msg3.ps_sec_prop.sgx_ps_sec_prop_desc);

        result
    };
    let mut attestation_tokens = colima::SgxAttestationTokens::new();
    attestation_tokens.set_msg3(msg3_proto);

    let msg3_quote_proto = serialize_quote(&msg3_quote);
    attestation_tokens.set_msg3_quote(msg3_quote_proto);

    attestation_tokens.set_msg3_sig(msg3_sig.to_vec());

    let pubkey_quote_proto = serialize_quote(&pubkey_quote);
    attestation_tokens.set_pubkey_quote(pubkey_quote_proto);

    attestation_tokens.set_pubkey_sig(pubkey_sig.to_vec());

    let mut colima = colima::TabascoRequest::new();
    colima.set_sgx_attestation_tokens(attestation_tokens);
    colima.set_context(context);

    Ok(colima.write_to_bytes()?)
}

pub fn parse_start_msg(
    parsed: &colima::TabascoRequest,
) -> (std::string::String, std::string::String) {
    let start_msg = parsed.get_start_msg();
    (
        start_msg.protocol.clone(),
        start_msg.firmware_version.clone(),
    )
}

pub fn serialize_start_msg(protocol: &str, firmware_version: &str) -> ColimaResult {
    let mut colima = colima::TabascoRequest::new();
    let mut start_msg = colima::StartMsg::new();
    start_msg.set_protocol(protocol.to_string());
    start_msg.set_firmware_version(firmware_version.to_string());
    colima.set_start_msg(start_msg);
    Ok(colima.write_to_bytes()?)
}

#[cfg(feature = "sgx_attestation")]
pub fn parse_msg1(
    parsed: &colima::TabascoRequest,
) -> (sgx_types::sgx_ra_context_t, sgx_types::sgx_ra_msg1_t, i32) {
    let context = parsed.get_context();
    let msg1_proto = parsed.get_msg1();
    let mut msg1 = sgx_types::sgx_ra_msg1_t::default();
    msg1.g_a.gx.copy_from_slice(msg1_proto.get_g_a().get_gx());
    msg1.g_a.gy.copy_from_slice(msg1_proto.get_g_a().get_gy());
    msg1.gid.copy_from_slice(msg1_proto.get_gid());
    let device_id = msg1_proto.get_device_id();

    (context, msg1, device_id)
}

#[cfg(feature = "sgx_attestation")]
pub fn serialize_msg1(
    context: sgx_types::sgx_ra_context_t,
    msg1: &sgx_types::sgx_ra_msg1_t,
    device_id: i32,
) -> ColimaResult {
    let mut g_a = colima::SgxEc256Public::new();
    g_a.set_gx(msg1.g_a.gx.to_vec());
    g_a.set_gy(msg1.g_a.gy.to_vec());
    let mut msg1_proto = colima::SgxMsg1::new();
    msg1_proto.set_g_a(g_a);
    msg1_proto.set_gid(msg1.gid.to_vec());
    msg1_proto.set_device_id(device_id);

    let mut colima = colima::TabascoRequest::new();
    colima.set_msg1(msg1_proto);
    colima.set_context(context);

    Ok(colima.write_to_bytes()?)
}

#[cfg(feature = "sgx_attestation")]
fn parse_msg2(proto: &colima::SgxMsg2) -> Result<sgx_types::sgx_ra_msg2_t, ColimaError> {
    let mut msg2 = sgx_types::sgx_ra_msg2_t::default();
    msg2.g_b.gx.copy_from_slice(proto.get_g_b().get_gx());
    msg2.g_b.gy.copy_from_slice(proto.get_g_b().get_gy());
    msg2.spid.id.copy_from_slice(&proto.get_spid());
    msg2.quote_type = proto.get_quote_type().try_into()?;
    msg2.kdf_id = proto.get_kdf_id().try_into()?;
    msg2.sign_gb_ga
        .x
        .copy_from_slice(proto.get_sign_gb_ga().get_x());
    msg2.sign_gb_ga
        .y
        .copy_from_slice(proto.get_sign_gb_ga().get_y());
    msg2.mac.copy_from_slice(&proto.get_mac());
    msg2.sig_rl_size = proto.get_sig_rl_size();

    Ok(msg2)
}

#[cfg(feature = "sgx_attestation")]
fn serialize_msg2(msg2: &sgx_types::sgx_ra_msg2_t) -> colima::SgxMsg2 {
    let mut proto = colima::SgxMsg2::new();
    let g_b = {
        let mut g_b = colima::SgxEc256Public::new();
        g_b.gx.resize(msg2.g_b.gx.len(), 0);
        g_b.gx.copy_from_slice(&msg2.g_b.gx);
        g_b.gy.resize(msg2.g_b.gy.len(), 0);
        g_b.gy.copy_from_slice(&msg2.g_b.gy);
        g_b
    };
    proto.set_g_b(g_b);
    proto.spid.resize(msg2.spid.id.len(), 0);
    proto.spid.copy_from_slice(&msg2.spid.id);
    proto.quote_type = msg2.quote_type.into();
    proto.kdf_id = msg2.kdf_id.into();
    let sign_gb_ga = {
        let mut sig = colima::SgxEc256Signature::new();
        sig.x.resize(msg2.sign_gb_ga.x.len(), 0);
        sig.x.copy_from_slice(&msg2.sign_gb_ga.x);
        sig.y.resize(msg2.sign_gb_ga.y.len(), 0);
        sig.y.copy_from_slice(&msg2.sign_gb_ga.y);
        sig
    };
    proto.set_sign_gb_ga(sign_gb_ga);
    proto.mac.resize(msg2.mac.len(), 0);
    proto.mac.copy_from_slice(&msg2.mac);
    proto.sig_rl_size = msg2.sig_rl_size;
    proto
}
