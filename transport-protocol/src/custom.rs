//! Custom and derived functionality relating to the transport protocol.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::transport_protocol;
#[cfg(feature = "sgx_attestation")]
use core::convert::TryInto;
use err_derive::Error;
use protobuf::{error::ProtobufError, Message, ProtobufEnum};
#[cfg(feature = "sgx_attestation")]
use sgx_types;
use std::{result::Result, string::ToString};

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "TransportProtocol: ProtobufError: {:?}.", _0)]
    ProtobufError(#[error(source)] ProtobufError),
    #[error(display = "TransportProtocol: Invalid response status: {:?}.", _0)]
    ResponseStatusError(i32),
    #[error(display = "TransportProtocol: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
}
type TransportProtocolResult = Result<std::vec::Vec<u8>, TransportProtocolError>;

/// Parse a request to the Runtime Manager.
pub fn parse_runtime_manager_request(buffer: &[u8]) -> Result<transport_protocol::RuntimeManagerRequest, TransportProtocolError> {
    Ok(protobuf::parse_from_bytes::<transport_protocol::RuntimeManagerRequest>(
        buffer,
    )?)
}

/// Parse a response from the Runtime Manager.
pub fn parse_runtime_manager_response(
    buffer: &[u8],
) -> Result<transport_protocol::RuntimeManagerResponse, TransportProtocolError> {
    Ok(protobuf::parse_from_bytes::<transport_protocol::RuntimeManagerResponse>(
        buffer,
    )?)
}

pub fn parse_proxy_attestation_server_request(buffer: &[u8]) -> Result<transport_protocol::ProxyAttestationServerRequest, TransportProtocolError> {
    Ok(protobuf::parse_from_bytes::<transport_protocol::ProxyAttestationServerRequest>(
        buffer,
    )?)
}

pub fn parse_proxy_attestation_server_response(buffer: &[u8]) -> Result<transport_protocol::ProxyAttestationServerResponse, TransportProtocolError> {
    Ok(protobuf::parse_from_bytes::<transport_protocol::ProxyAttestationServerResponse>(
        buffer,
    )?)
}

#[cfg(feature = "sgx_attestation")]
fn parse_report_body(
    proto: &transport_protocol::SgxReportBody,
) -> Result<sgx_types::sgx_report_body_t, TransportProtocolError> {
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
fn parse_quote(proto: &transport_protocol::SgxQuote) -> Result<sgx_types::sgx_quote_t, TransportProtocolError> {
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
pub fn serialize_quote(quote: &sgx_types::sgx_quote_t) -> transport_protocol::SgxQuote {
    let mut result = transport_protocol::SgxQuote::default();
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
        let mut ret = transport_protocol::SgxReportBody::default();
        ret.cpu_svn.resize(quote.report_body.cpu_svn.svn.len(), 0);
        ret.cpu_svn.copy_from_slice(&quote.report_body.cpu_svn.svn);
        ret.misc_select = quote.report_body.misc_select;
        ret.isv_ext_prod_id
            .resize(quote.report_body.isv_ext_prod_id.len(), 0);
        ret.isv_ext_prod_id
            .copy_from_slice(&quote.report_body.isv_ext_prod_id);
        let attributes = {
            let mut attributes = transport_protocol::SgxAttributes::default();
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

/// Serialize a program binary.
pub fn serialize_program(program_buffer: &[u8], file_name: &str) -> TransportProtocolResult {
    let mut program = transport_protocol::Program::new();
    program.set_file_name(file_name.to_string());
    program.set_code(program_buffer.to_vec());
    let mut abs = transport_protocol::RuntimeManagerRequest::new();
    abs.set_program(program);

    Ok(abs.write_to_bytes()?)
}

/// Serialize a (static) data package and its package ID.
pub fn serialize_program_data(data_buffer: &[u8], file_name: &str) -> TransportProtocolResult {
    let mut data = transport_protocol::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_file_name(file_name.to_string());
    let mut transport_protocol = transport_protocol::RuntimeManagerRequest::new();
    transport_protocol.set_data(data);

    Ok(transport_protocol.write_to_bytes()?)
}

/// Serialize the request for querying enclave state.
pub fn serialize_request_enclave_state() -> TransportProtocolResult {
    let command = transport_protocol::RequestState::new();
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_state(command);

    Ok(request.write_to_bytes()?)
}

/// Serialize a stream data package and its package ID.
pub fn serialize_stream(data_buffer: &[u8], file_name: &str) -> TransportProtocolResult {
    let mut data = transport_protocol::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_file_name(file_name.to_string());
    let mut transport_protocol = transport_protocol::RuntimeManagerRequest::new();
    transport_protocol.set_stream(data);

    Ok(transport_protocol.write_to_bytes()?)
}

/// Serialize the request for querying the result.
pub fn serialize_request_result(file_name : &str) -> TransportProtocolResult {
    let mut command = transport_protocol::RequestResult::new();
    command.set_file_name(file_name.to_string());
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_result(command);

    Ok(request.write_to_bytes()?)
}

/// Serialize the request for shutting down the enclave.
pub fn serialize_request_shutdown() -> TransportProtocolResult {
    let command = transport_protocol::RequestShutdown::new();
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_shutdown(command);

    Ok(request.write_to_bytes()?)
}

pub fn serialize_request_proxy_psa_attestation_token(challenge: &[u8]) -> TransportProtocolResult {
    let mut rpat = transport_protocol::RequestProxyPsaAttestationToken::new();
    rpat.set_challenge(challenge.to_vec());
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_proxy_psa_attestation_token(rpat);

    Ok(request.write_to_bytes()?)
}

/// Serialize the request for signalling the next round of computation.
pub fn serialize_request_next_round() -> TransportProtocolResult {
    let command = transport_protocol::RequestNextRound::new();
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_next_round(command);

    Ok(request.write_to_bytes()?)
}

pub fn parse_request_proxy_psa_attestation_token(
    proto: &transport_protocol::RequestProxyPsaAttestationToken,
) -> std::vec::Vec<u8> {
    proto.get_challenge().to_vec()
}

pub fn serialize_sgx_collateral(collateral: &transport_protocol::SgxCollateral) -> TransportProtocolResult {
    return Ok(collateral.write_to_bytes()?);
}

pub fn parse_cert_chain(chain: &transport_protocol::CertChain) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    return (chain.get_root_cert().to_vec(), chain.get_enclave_cert().to_vec())
}

pub fn serialize_proxy_psa_attestation_token(
    token: &[u8],
    pubkey: &[u8],
    device_id: i32,
) -> TransportProtocolResult {
    let mut pat_proto = transport_protocol::ProxyPsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_pubkey(pubkey.to_vec());
    pat_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request = transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_proxy_psa_attestation_token(pat_proto);

    Ok(proxy_attestation_server_request.write_to_bytes()?)
}

pub fn serialize_nitro_attestation_doc(doc: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut nad_proto = transport_protocol::NitroAttestationDoc::new();
    nad_proto.set_doc(doc.to_vec());
    nad_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request = transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_nitro_attestation_doc(nad_proto);

    Ok(proxy_attestation_server_request.write_to_bytes()?)
}

pub fn serialize_certificate(cert: &[u8]) -> TransportProtocolResult {
    let mut proto_cert = transport_protocol::Cert::new();
    proto_cert.set_data(cert.to_vec());
    let mut rmr = transport_protocol::RuntimeManagerResponse::new();
    rmr.set_cert(proto_cert);
    return Ok(rmr.write_to_bytes()?);
}

pub fn parse_proxy_psa_attestation_token(
    proto: &transport_protocol::ProxyPsaAttestationToken,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, i32) {
    (
        proto.get_token().to_vec(),
        proto.get_pubkey().to_vec(),
        proto.get_device_id(),
    )
}

pub fn serialize_native_psa_attestation_token(token: &[u8], csr: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut pat_proto = transport_protocol::NativePsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_csr(csr.to_vec());
    pat_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request = transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_native_psa_attestation_token(pat_proto);

    Ok(proxy_attestation_server_request.write_to_bytes()?)
}

pub fn parse_native_psa_attestation_token(
    proto: &transport_protocol::NativePsaAttestationToken,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, i32) {
    (proto.get_token().to_vec(), proto.get_csr().to_vec(), proto.get_device_id())
}

pub fn parse_nitro_attestation_doc(
    proto: &transport_protocol::NitroAttestationDoc,
) -> (std::vec::Vec<u8>, i32) {
    (proto.get_doc().to_vec(), proto.get_device_id())
}

pub fn parse_sgx_attestation_init(proto: &transport_protocol::SgxAttestationInit) -> (std::vec::Vec<u8>, i32) {
    (proto.get_public_key().to_vec(), proto.get_device_id())
}

pub fn serialize_sgx_attestation_init(pubkey: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut attest_init_proto = transport_protocol::SgxAttestationInit::new();
    attest_init_proto.set_public_key(pubkey.to_vec());
    attest_init_proto.set_device_id(device_id);
    let mut transport_protocol = transport_protocol::ProxyAttestationServerResponse::new();
    transport_protocol.set_sgx_attestation_init(attest_init_proto);

    Ok(transport_protocol.write_to_bytes()?)
}

pub fn serialize_cert_chain(enclave_cert: &[u8], root_cert: &[u8]) -> TransportProtocolResult {
    let mut cert_chain = transport_protocol::CertChain::new();
    cert_chain.set_root_cert(root_cert.to_vec());
    cert_chain.set_enclave_cert(enclave_cert.to_vec());
    let mut response = transport_protocol::ProxyAttestationServerResponse::new();
    response.set_cert_chain(cert_chain);
    return Ok(response.write_to_bytes()?);
}

#[cfg(feature = "sgx_attestation")]
pub fn parse_sgx_attestation_challenge(
    parsed: &transport_protocol::ProxyAttestationServerResponse,
) -> Result<
    (
        sgx_types::sgx_ra_context_t,
        sgx_types::sgx_ra_msg2_t,
        [u8; 16],
    ),
    TransportProtocolError,
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
) -> TransportProtocolResult {
    let transport_protocol = {
        let attestation_challenge = {
            let msg2_proto = serialize_msg2(msg2);

            let mut attestation_challenge = transport_protocol::SgxAttestationChallenge::new();
            attestation_challenge
                .challenge
                .resize(pubkey_challenge.len(), 0);
            attestation_challenge
                .challenge
                .copy_from_slice(&pubkey_challenge);
            attestation_challenge.set_msg2(msg2_proto);

            attestation_challenge
        };

        let mut proto = transport_protocol::ProxyAttestationServerResponse::new();
        proto.set_sgx_attestation_challenge(attestation_challenge);
        proto.set_context(context);
        proto
    };

    Ok(transport_protocol.write_to_bytes()?)
}

pub fn serialize_psa_attestation_init(challenge: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut request = transport_protocol::ProxyAttestationServerResponse::new();
    let mut pai = transport_protocol::PsaAttestationInit::new();
    pai.set_challenge(challenge.to_vec());
    pai.set_device_id(device_id);
    request.set_psa_attestation_init(pai);
    Ok(request.write_to_bytes()?)
}

pub fn parse_psa_attestation_init(
    pai: &transport_protocol::PsaAttestationInit,
) -> Result<(std::vec::Vec<u8>, i32), TransportProtocolError> {
    Ok((pai.get_challenge().to_vec(), pai.get_device_id()))
}

/// Serialize the request for querying the hash of the provisioned program.
#[deprecated]
pub fn serialize_request_pi_hash(file_name : &str) -> TransportProtocolResult {
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    let mut rph = transport_protocol::RequestPiHash::new();
    rph.set_file_name(file_name.to_string());
    request.set_request_pi_hash(rph);
    Ok(request.write_to_bytes()?)
}

/// Serialize the request for querying the enclave policy.
pub fn serialize_request_policy_hash() -> TransportProtocolResult {
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    let rph = transport_protocol::RequestPolicyHash::new();
    request.set_request_policy_hash(rph);
    Ok(request.write_to_bytes()?)
}

/// Serialize the request for querying state of the enclave.
pub fn serialize_machine_state(machine_state: u8) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    response.set_status(transport_protocol::ResponseStatus::SUCCESS);
    let mut state = transport_protocol::State::new();
    let slice = &vec![machine_state];

    state.state.resize(slice.len(), 0);
    state.state.copy_from_slice(slice);
    response.set_state(state);
    Ok(response.write_to_bytes()?)
}

/// Serialize a response containing the program hash.
pub fn serialize_pi_hash(hash: &[u8]) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    response.set_status(transport_protocol::ResponseStatus::SUCCESS);
    let mut pi_hash = transport_protocol::PiHash::new();
    pi_hash.data.resize(hash.len(), 0);
    pi_hash.data.copy_from_slice(hash);
    response.set_pi_hash(pi_hash);
    Ok(response.write_to_bytes()?)
}

/// Serialize a response containing the policy hash.
pub fn serialize_policy_hash(hash: &[u8]) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    response.set_status(transport_protocol::ResponseStatus::SUCCESS);
    let mut policy_hash = transport_protocol::PolicyHash::new();
    policy_hash.data.resize(hash.len(), 0);
    policy_hash.data.copy_from_slice(hash);
    response.set_policy_hash(policy_hash);
    Ok(response.write_to_bytes()?)
}

/// Serialize an empty response.
pub fn serialize_empty_response(status: i32) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();
    let encoded_status =
        transport_protocol::ResponseStatus::from_i32(status).ok_or(TransportProtocolError::ResponseStatusError(status))?;
    response.set_status(encoded_status);

    Ok(response.write_to_bytes()?)
}

/// Serialize a response containing the computation result.
pub fn serialize_result(status: i32, data_opt: Option<std::vec::Vec<u8>>) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    let encoded_status =
        transport_protocol::ResponseStatus::from_i32(status).ok_or(TransportProtocolError::ResponseStatusError(status))?;

    response.set_status(encoded_status);

    if let Some(ref data) = data_opt {
        let mut result = transport_protocol::Result::new();
        result.data.resize(data.len(), 0);
        result.data.copy_from_slice(&data);
        response.set_result(result);
    }

    Ok(response.write_to_bytes()?)
}

pub fn parse_result(
    response: &transport_protocol::RuntimeManagerResponse,
) -> Result<Option<std::vec::Vec<u8>>, TransportProtocolError> {
    let status = response.get_status();
    let decoded_status = match status {
        transport_protocol::ResponseStatus::UNSET => -1,
        transport_protocol::ResponseStatus::SUCCESS => 0,
        transport_protocol::ResponseStatus::FAILED_INVALID_ROLE => 1,
        transport_protocol::ResponseStatus::FAILED_NOT_READY => 2,
        transport_protocol::ResponseStatus::FAILED_GENERIC => 3,
        transport_protocol::ResponseStatus::FAILED_VM_ERROR => 4,
        transport_protocol::ResponseStatus::FAILED_ERROR_CODE_RETURNED => 5,
        transport_protocol::ResponseStatus::FAILED_INVALID_REQUEST => 6,
    };
    if status != transport_protocol::ResponseStatus::SUCCESS {
        return Err(TransportProtocolError::ResponseStatusError(decoded_status));
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
fn parse_msg3(proto: &transport_protocol::SgxMsg3) -> (sgx_types::sgx_ra_msg3_t, i32) {
    //let proto = abs.get_msg3();
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
    parsed: &transport_protocol::ProxyAttestationServerRequest,
) -> Result<
    (
        sgx_types::sgx_ra_msg3_t, // msg3
        sgx_types::sgx_quote_t,   // msg3_quote
        std::vec::Vec<u8>,        // msg3_sig
        sgx_types::sgx_quote_t,   // collateral_quote
        std::vec::Vec<u8>,        // collateral_sig
        std::vec::Vec<u8>,        // csr
        i32,                      // device_id
    ),
    TransportProtocolError,
> {
    let attest_tokens = parsed.get_sgx_attestation_tokens();
    let (msg3, device_id) = parse_msg3(attest_tokens.get_msg3());
    let msg3_quote = parse_quote(&attest_tokens.get_msg3_quote())?;
    let msg3_sig = {
        let proto = attest_tokens.get_msg3_sig();
        proto.to_vec()
    };
    let collateral_quote = parse_quote(&attest_tokens.get_collateral_quote())?;
    let collateral_sig = {
        let sig = attest_tokens.get_collateral_sig();
        sig.to_vec()
    };

    let collateral = attest_tokens.get_collateral();
    let csr = collateral.get_csr();

    Ok((
        msg3,
        msg3_quote,
        msg3_sig,
        collateral_quote,
        collateral_sig,
        csr.to_vec(),
        device_id,
    ))
}

#[cfg(feature = "sgx_attestation")]
pub fn serialize_sgx_attestation_tokens(
    context: sgx_types::sgx_ra_context_t,
    msg3: &sgx_types::sgx_ra_msg3_t,
    msg3_quote: &sgx_types::sgx_quote_t,
    msg3_sig: &std::vec::Vec<u8>,
    collateral_quote: &sgx_types::sgx_quote_t,
    collateral_sig: &std::vec::Vec<u8>,
    csr: &std::vec::Vec<u8>,
    device_id: i32,
) -> TransportProtocolResult {
    let msg3_proto = {
        let mut result = transport_protocol::SgxMsg3::new();
        result.set_device_id(device_id);
        result.mac.resize(msg3.mac.len(), 0);
        result.mac.copy_from_slice(&msg3.mac);
        let g_a = {
            let mut ret = transport_protocol::SgxEc256Public::default();
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
    let mut attestation_tokens = transport_protocol::SgxAttestationTokens::new();
    attestation_tokens.set_msg3(msg3_proto);

    let msg3_quote_proto = serialize_quote(&msg3_quote);
    attestation_tokens.set_msg3_quote(msg3_quote_proto);

    attestation_tokens.set_msg3_sig(msg3_sig.to_vec());

    let collateral_quote_proto = serialize_quote(&collateral_quote);
    attestation_tokens.set_collateral_quote(collateral_quote_proto);

    attestation_tokens.set_collateral_sig(collateral_sig.to_vec());

    let mut collateral = transport_protocol::SgxCollateral::new();
    collateral.set_csr(csr.to_vec());

    attestation_tokens.set_collateral(collateral);

    let mut transport_protocol = transport_protocol::ProxyAttestationServerRequest::new();
    transport_protocol.set_sgx_attestation_tokens(attestation_tokens);
    transport_protocol.set_context(context);

    Ok(transport_protocol.write_to_bytes()?)
}

pub fn parse_start_msg(
    parsed: &transport_protocol::ProxyAttestationServerRequest,
) -> (std::string::String, std::string::String) {
    let start_msg = parsed.get_start_msg();
    (
        start_msg.protocol.clone(),
        start_msg.firmware_version.clone(),
    )
}

pub fn serialize_start_msg(protocol: &str, firmware_version: &str) -> TransportProtocolResult {
    let mut transport_protocol = transport_protocol::ProxyAttestationServerRequest::new();
    let mut start_msg = transport_protocol::StartMsg::new();
    start_msg.set_protocol(protocol.to_string());
    start_msg.set_firmware_version(firmware_version.to_string());
    transport_protocol.set_start_msg(start_msg);
    Ok(transport_protocol.write_to_bytes()?)
}

#[cfg(feature = "sgx_attestation")]
pub fn parse_msg1(
    parsed: &transport_protocol::ProxyAttestationServerRequest,
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
) -> TransportProtocolResult {
    let mut g_a = transport_protocol::SgxEc256Public::new();
    g_a.set_gx(msg1.g_a.gx.to_vec());
    g_a.set_gy(msg1.g_a.gy.to_vec());
    let mut msg1_proto = transport_protocol::SgxMsg1::new();
    msg1_proto.set_g_a(g_a);
    msg1_proto.set_gid(msg1.gid.to_vec());
    msg1_proto.set_device_id(device_id);

    let mut transport_protocol = transport_protocol::ProxyAttestationServerRequest::new();
    transport_protocol.set_msg1(msg1_proto);
    transport_protocol.set_context(context);

    Ok(transport_protocol.write_to_bytes()?)
}

#[cfg(feature = "sgx_attestation")]
fn parse_msg2(proto: &transport_protocol::SgxMsg2) -> Result<sgx_types::sgx_ra_msg2_t, TransportProtocolError> {
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
fn serialize_msg2(msg2: &sgx_types::sgx_ra_msg2_t) -> transport_protocol::SgxMsg2 {
    let mut proto = transport_protocol::SgxMsg2::new();
    let g_b = {
        let mut g_b = transport_protocol::SgxEc256Public::new();
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
        let mut sig = transport_protocol::SgxEc256Signature::new();
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
