#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# Policy generator
#
# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

import argparse
import subprocess
import datetime
import os.path
from os import path

identity_template = '\n\t\t{"certificate": "<CERT>",\n\t\t"id": <ID_NUM>,\n\t\t"roles": [<ROLES>]}'

def get_enclave_hashes(template):
    field_string = ''
    if path.exists('css.bin'):
        subprocess.call(['dd', 'skip=960', 'count=32', 'if=css.bin', 'of=hash.bin', 'bs=1'])
        hash_hex = subprocess.check_output(['xxd', '-ps', '-cols', '32', 'hash.bin'])
        hash_hex = hash_hex.replace('\n', '')
        field_string = field_string + '    "mexico_city_hash_sgx": "' + hash_hex + '",'
        # right now, we are totally faking TrustZone Hashes, so we're making it match SGX
        field_string = field_string + '\n    "mexico_city_hash_tz": "' + hash_hex + '",'
    if path.exists('../mexico-city/PCR0'):
        pcr0 = open('../mexico-city/PCR0').read().replace("\n", "")
        field_string = field_string + '\n    "mexico_city_hash_nitro": "' + pcr0 + '",'

    return template.replace('<MEXICO_CITY_HASHES>', field_string)

def get_pi_hash(pi_file, template):
    hash_result = subprocess.check_output(['sha256sum', pi_file])
    fields = hash_result.split()
    return template.replace('<PI_HASH>', fields[0])

def int_list_to_json(lst):
    rst = '[';
    is_first = True;
    for i in lst:
        if is_first:
            rst += str(i);
            is_first = False;
        else:
            rst += ', ' + str(i);
    rst += ']';
    return rst;

def data_provision_order(args):
    argument = args.data_provision_order
    if argument is None:
        return int_list_to_json([])
    else:
        return int_list_to_json(argument)

def streaming_order(args):
    argument = args.streaming_order
    if argument is None:
        return int_list_to_json([])
    else:
        return int_list_to_json(argument)

parser = argparse.ArgumentParser('Generate a Veracruz Policy file from a template')
parser.add_argument('--identity', '-i', help='Information for an identity', required=True, nargs=2, metavar=('cert', 'roles'), action='append')
parser.add_argument('--sinaloa-url', help='URL where the Sinaloa instance will be started', required=True)
parser.add_argument('--tabasco-url', help='URL where the Tabasco instance will be started', required=True)
parser.add_argument('--output-policy-file', '-o', help='Location of the output policy file', required=True)
parser.add_argument('--template-file', '-t', help='Location of the input template file', required=True)
parser.add_argument('--certificate-lifetime-in-hours', help='The expiry for the server certificate will be set to this number of hours in the future', required=True)
parser.add_argument('--data-provision-order', '-p', type=int, nargs='+', help='The data provision order', required=False)
parser.add_argument('--streaming-order', '-s', type=int, nargs='+', help='The data provision order', required=False)
parser.add_argument('--pi-binary', help='Filename of the binary (wasm) of the PI', required=True)
parser.add_argument('--debug-flag', help='Debug flag', required=False, type=bool, default=False)
parser.add_argument('--execution-strategy', '-x', help='Execution strategy for the computation', required=True)

args = parser.parse_args()
template_file = open(args.template_file);
template = template_file.read();
template_file.close();

id_num = 0
identities_string = ''
for this_identity in args.identity:
    if id_num != 0:
        identities_string += ',\n'  

    id_cert_file = open(this_identity[0]);
    id_cert = id_cert_file.read();
    id_cert_file.close();
    id_cert = id_cert.replace('\n', '');
    # add the \n after the -----BEGIN CERTIFICATE----- back in
    id_cert = id_cert.replace('-----BEGIN CERTIFICATE-----', '-----BEGIN CERTIFICATE-----\\n');
    # add the \n before the -----END CERTIFICATE----- back in
    id_cert = id_cert.replace('-----END CERTIFICATE', '\\n-----END CERTIFICATE')

    id_string = identity_template

    id_string = id_string.replace('<CERT>', id_cert);
    id_string = id_string.replace('<ID_NUM>', str(id_num));
    id_string = id_string.replace('<ROLES>', this_identity[1])

    identities_string += id_string

    id_num += 1

policy = template

policy = policy.replace('<IDENTITIES>', identities_string)

policy = policy.replace('<SINALOA_URL>', args.sinaloa_url)

policy = policy.replace('<DATA_PROVISION_ORDER>', data_provision_order(args))
policy = policy.replace('<STREAMING_ORDER>', streaming_order(args))

# set the "enclave_cert_expiry" field
expiry =  datetime.datetime.now() + datetime.timedelta(hours=int(args.certificate_lifetime_in_hours))
policy = policy.replace('<YEAR>', str(expiry.year))
policy = policy.replace('<MONTH>', str(expiry.month))
policy = policy.replace('<DAY>', str(expiry.day))
policy = policy.replace('<HOUR>', str(expiry.hour))
policy = policy.replace('<MINUTE>', str(expiry.minute))
policy = policy.replace('<SECOND>', str(expiry.second))

# set the tabasco URL
policy = policy.replace('<TABASCO_URL>', args.tabasco_url)

# debug info
policy = policy.replace('<DEBUG_FLAG>', str(args.debug_flag).lower())

policy = get_enclave_hashes(policy)
policy = get_pi_hash(args.pi_binary, policy)

# execution strategy
policy = policy.replace('<EXECUTION_STRATEGY>', args.execution_strategy)

policy_file = open(args.output_policy_file, 'w');
policy_file.write(policy);
policy_file.close()



