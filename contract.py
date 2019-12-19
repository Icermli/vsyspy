from .crypto import *
from .deser import *
from .setting import ContractMeta
from . import deser

import struct
import base58
import itertools
import logging

logger = logging.getLogger(__name__)


class Contract(object):
    def __init__(self, language_code='vdds', language_version=1, trigger=None, descriptor=None, state_var=None,
                 textual=None, split=False):
        self.contract_lang_code = language_code_builder(language_code)
        self.contract_lang_ver = language_version_builder(language_version)
        if trigger is None:
            self.contract_trigger = ContractDefaults.trigger
        else:
            self.contract_trigger = bytes_builder_from_list(trigger)

        if descriptor is None:
            if split is False:
                self.contract_descriptor = ContractDefaults.descriptor_without_split
            else:
                self.contract_descriptor = ContractDefaults.descriptor_with_split
        else:
            self.contract_descriptor = bytes_builder_from_list(descriptor)

        if state_var is None:
            self.contract_state_var = ContractDefaults.state_var
        else:
            self.contract_state_var = bytes_builder_from_list(state_var)

        if textual is None:
            if split is False:
                self.contract_textual = ContractDefaults.textual_without_split
            else:
                self.contract_textual = ContractDefaults.textual_with_split
        else:
            self.contract_textual = deser.serialize_arrays(textual)
        self.contract_bytes = self.contract_lang_code + self.contract_lang_ver + self.contract_trigger \
                              + self.contract_descriptor + self.contract_state_var + self.contract_textual

        self.contract_bytes_string = bytes2str(base58.b58encode(self.contract_bytes))


def language_code_builder(code):
    if len(code) == ContractMeta.language_code_byte_length:
        language_code = deser.serialize_string(code)
        return language_code
    else:
        logging.error("Wrong language code length")
        raise Exception("Wrong language code length")


def language_version_builder(version):
    if len(struct.pack(">I", version)) == ContractMeta.language_version_byte_length:
        return struct.pack(">I", version)
    else:
        logging.error("Wrong language version length")
        raise Exception("Wrong language code length")


def bytes_builder_from_list(input_list):
    if type(input_list) is list:
        return deser.serialize_array(deser.serialize_arrays(input_list))
    else:
        logging.error("The input should be a list")


def serialize_data(data_entry_list):
    custom_data_stack = []
    if not type(data_entry_list) is list:
        data_entry_list = [data_entry_list]
    for data in data_entry_list:
        custom_data_stack.append(data.bytes)
    return serialize_array(custom_data_stack)


def data_entry_from_base58_str(str_object):
    base58_str = base58.b58decode(str_object)
    return data_entries_from_bytes(base58_str)


def data_entries_from_bytes(bytes_object):
    length = struct.unpack(">H", bytes_object[0:2])[0]
    all_data = []
    pos_drift = 2
    for pos in range(length):
        [array_info, pos_drift] = parse_data_entry_array_size(bytes_object, pos_drift)
        all_data.append(array_info)
    return all_data


def parse_data_entry_array_size(bytes_object, start_position):
    if bytes_object[start_position: start_position + 1] == Type.public_key:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.key_length + 1]),
                start_position + Type.key_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.address:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.address_length + 1]),
                start_position + Type.address_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.amount:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.amount_length + 1]),
                start_position + Type.amount_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.int32:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.int32_length + 1]),
                start_position + Type.int32_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.short_text:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + struct.unpack(">H", bytes_object[
                                                                                                       start_position + 1:start_position + 3])[
            0] + 3]),
                start_position + struct.unpack(">H", bytes_object[start_position + 1: start_position + 3])[0] + 3)
    elif bytes_object[start_position: start_position + 1] == Type.contract_account:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.address_length + 1]),
                start_position + Type.address_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.token_id:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.token_address_length + 1]),
                start_position + Type.token_address_length + 1)
    elif bytes_object[start_position: start_position + 1] == Type.timestamp:
        return (data_entry_from_bytes(bytes_object[start_position:start_position + Type.amount_length + 1]),
                start_position + Type.amount_length + 1)


def data_entry_from_bytes(bytes_object):
    if len(bytes_object) == 0:
        raise ValueError("Invalid DataEntry %s" % str(bytes_object))
    elif bytes_object[0:1] == Type.public_key:
        return DataEntry(bytes2str(base58.b58encode(bytes_object[1:])), bytes_object[0:1])
    elif bytes_object[0:1] == Type.address:
        return DataEntry(bytes2str(base58.b58encode(bytes_object[1:])), bytes_object[0:1])
    elif bytes_object[0:1] == Type.amount:
        return DataEntry(struct.unpack(">Q", bytes_object[1:])[0], bytes_object[0:1])
    elif bytes_object[0:1] == Type.int32:
        return DataEntry(struct.unpack(">I", bytes_object[1:])[0], bytes_object[0:1])
    elif bytes_object[0:1] == Type.short_text:
        return DataEntry(bytes2str(bytes_object[3:]), bytes_object[0:1])
    elif bytes_object[0:1] == Type.contract_account:
        return DataEntry(bytes2str(base58.b58encode(bytes_object[1:])), bytes_object[0:1])
    elif bytes_object[0:1] == Type.token_id:
        return DataEntry(bytes2str(base58.b58encode(bytes_object[1:])), bytes_object[0:1])
    elif bytes_object[0:1] == Type.timestamp:
        return DataEntry(struct.unpack(">Q", bytes_object[1:])[0], bytes_object[0:1])


def check_data_type(data, data_type):
    if data_type == Type.public_key:
        data_bytes = base58.b58decode(data)
        return len(data_bytes) == Type.key_length
    elif data_type == Type.address:
        data_bytes = base58.b58decode(data)
        return len(data_bytes) == Type.address_length
    elif data_type == Type.amount:
        data_bytes = struct.pack(">Q", data)
        return len(data_bytes) == Type.amount_length and struct.unpack(">Q", data_bytes)[0] > 0
    elif data_type == Type.int32:
        data_bytes = struct.pack(">I", data)
        return len(data_bytes) == Type.int32_length and struct.unpack(">I", data_bytes)[0] > 0
    elif data_type == Type.short_text:
        data_bytes = serialize_array(str2bytes(data))
        return struct.unpack(">H", data_bytes[0:2])[0] + 2 == len(data_bytes) and len(
            data_bytes) <= Type.max_short_text_size + 2
    else:
        return True


class DataEntry:
    def __init__(self, data, data_type):
        if not check_data_type(data, data_type):
            raise ValueError("Invalid DataEntry data: %s, type: %s" % (str(data), str(data_type)))
        if data_type == Type.public_key:
            self.data_bytes = base58.b58decode(data)
            self.data_type = 'public_key'
        elif data_type == Type.address:
            self.data_bytes = base58.b58decode(data)
            self.data_type = 'address'
        elif data_type == Type.amount:
            self.data_bytes = struct.pack(">Q", data)
            self.data_type = 'amount'
        elif data_type == Type.int32:
            self.data_bytes = struct.pack(">I", data)
            self.data_type = 'int32'
        elif data_type == Type.short_text:
            self.data_bytes = serialize_array(str2bytes(data))
            self.data_type = 'short_text'
        elif data_type == Type.contract_account:
            self.data_bytes = base58.b58decode(data)
            self.data_type = 'contract_account'
        elif data_type == Type.token_id:
            self.data_bytes = base58.b58decode(data)
            self.data_type = 'token_id'
        elif data_type == Type.timestamp:
            self.data_bytes = struct.pack(">Q", data)
            self.data_type = 'timestamp'
        self.data = data
        self.bytes = data_type + self.data_bytes


class Type:
    public_key = struct.pack(">B", 1)
    key_length = 32
    address = struct.pack(">B", 2)
    address_length = 26
    amount = struct.pack(">B", 3)
    amount_length = 8
    int32 = struct.pack(">B", 4)
    int32_length = 4
    short_text = struct.pack(">B", 5)
    max_short_text_size = 140
    contract_account = struct.pack(">B", 6)
    contract_account_length = 26
    account = struct.pack(">B", 7)
    token_id = struct.pack(">B", 8)
    token_address_length = 30
    timestamp = struct.pack(">B", 9)
    boolean = struct.pack(">B", 10)
    balance = struct.pack(">B", 11)


data_type_list = {value: bytes([int(key)]) for key, value in ContractMeta.data_type_list.items()}
function_type_map = {value: bytes([int(key[1:])]) for key, value in ContractMeta.function_type_map.items()}

def opc_assert_is_caller_origin():
    return ContractMeta.assert_opc + ContractMeta.is_caller_origin_assert

def opc_assert_is_signer_origin():
    return ContractMeta.assert_opc + ContractMeta.is_signer_origin_assert

def opc_load_signer():
    return ContractMeta.load_opc + ContractMeta.signer_load

def opc_load_caller():
    return ContractMeta.load_opc + ContractMeta.caller_load

def opc_cdbv_set():
    return ContractMeta.cdbv_opc + ContractMeta.set_cdbv

def opc_cdbvr_get():
    return ContractMeta.cdbvr_opc + ContractMeta.get_cdbvr

def opc_tdb_new_token():
    return ContractMeta.tdb_opc + ContractMeta.new_token_tdb

def opc_tdb_split():
    return ContractMeta.tdb_opc + ContractMeta.split_tdb

def opc_tdbr_opc_max():
    return ContractMeta.tdbr_opc + ContractMeta.get_tdbr

def opc_tdbr_opc_total():
    return ContractMeta.tdbr_opc + ContractMeta.total_tdbr

def opc_tdba_deposit():
    return ContractMeta.tdba_opc + ContractMeta.deposit_tdba

def opc_tdba_withdraw():
    return ContractMeta.tdba_opc + ContractMeta.withdraw_tdba

def opc_tdba_transfer():
    return ContractMeta.tdba_opc + ContractMeta.transfer_tdba

def opc_tdbar_balance():
    return ContractMeta.tdbar_opc + ContractMeta.balance_tdbar

def opc_return_value():
    return ContractMeta.return_opc + bytes([1])

def language_code_builder(code):
    if len(code) == ContractMeta.language_code_byte_length:
        language_code = deser.serialize_string(code)
        return language_code
    else:
        logging.error("Wrong language code length")
        raise Exception("Wrong language code length")

def language_version_builder(version):
    try:
        if len(struct.pack(">I", version)) == ContractMeta.language_version_byte_length:
            return struct.pack(">I", version)
        else:
            logging.error("Wrong language version length")
            raise Exception("Wrong language code length")
    except:
        print("Wrong language version length")


def bytes_builder_from_list(input_list):
    if type(input_list) is list:
        return deser.serialize_array(deser.serialize_arrays(input_list))
    else:
        logging.error("The input should be a list")

def textual_fun_gen(name, ret, para):
    func_byte = deser.serialize_array(deser.serialize_string(name))
    ret_byte = deser.serialize_array(deser.serialize_arrays([deser.serialize_string(r) for r in ret]))
    para_byte = deser.serialize_arrays([deser.serialize_string(p) for p in para])
    textual = func_byte + ret_byte + para_byte
    return textual

def init_func_bytes():
    return textual_fun_gen("init", [], ContractMeta.init_para)

def supersede_func_bytes():
    return textual_fun_gen("supersede", [], ContractMeta.supersede_para)

def issue_func_bytes():
    return textual_fun_gen("issue", [], ContractMeta.issue_para)

def destroy_func_bytes():
    return textual_fun_gen("destroy", [], ContractMeta.destroy_para)

def split_func_bytes():
    return textual_fun_gen("split", [], ContractMeta.split_para)

def send_func_bytes():
    return textual_fun_gen("send", [], ContractMeta.send_para)

def transfer_func_bytes():
    return textual_fun_gen("transfer", [], ContractMeta.transfer_para)

def deposit_func_bytes():
    return textual_fun_gen("deposit", [], ContractMeta.deposit_para)

def withdraw_func_bytes():
    return textual_fun_gen("withdraw", [], ContractMeta.withdraw_para)

def total_supply_func_bytes():
    return textual_fun_gen("totalSupply", ["total"], ContractMeta.total_supply_para)

def max_supply_func_bytes():
    return textual_fun_gen("maxSupply", ["max"], ContractMeta.max_supply_para)

def balance_of_func_bytes():
    return textual_fun_gen("balanceOf", ["balance"], ContractMeta.balance_of_para)

def get_issuer_func_bytes():
    return textual_fun_gen("getIssuer", ["issuer"], ContractMeta.get_issuer_para)


def state_var_random_gen():
    fixed_size = 2
    state_var = bytearray(os.urandom(fixed_size))
    return state_var

def state_var_gen(state_vars):
    state_vars = deser.serialize_arrays(state_vars)
    return state_vars

def func_gen(fun_idx, fun_type, proto_type, list_opc):
    fun = fun_idx + fun_type + proto_type + list_opc
    return fun

def init_fun_gen():
    fun = func_gen(struct.pack(">H", ContractMeta.init), function_type_map.get("onInit"),
                   proto_type_gen(ContractMeta.non_return_type, [data_type_list.get('Amount'), data_type_list.get('Amount'), data_type_list.get('ShortText')]), list_opc_gen([opc_load_signer(), opc_cdbv_set(), opc_cdbv_set(), opc_tdb_new_token()], [opc_load_signer_index(), init_opc_cdbv_set_signer_index(), init_opc_cdbv_set_maker_index(), init_opc_tdb_new_token_index()]))
    return fun

def supersede_fun_gen():
    fun = func_gen(struct.pack(">H", ContractMeta.supersede), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, supersede_para_type()), list_opc_gen(supersede_opc(), supersede_opc_index()))
    return fun

def supersede_fun_without_split_gen():
    fun = func_gen(supersede_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, supersede_para_type()), list_opc_gen(supersede_opc(), supersede_opc_index()))
    return fun

def issue_fun_gen():
    fun = func_gen(issue_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, issue_para_type()), list_opc_gen(issue_opc(), issue_opc_index()))
    return fun

def issue_fun_without_split_gen():
    fun = func_gen(issue_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, issue_para_type()), list_opc_gen(issue_opc(), issue_opc_index()))
    return fun

def destroy_fun_gen():
    fun = func_gen(destroy_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, destroy_para_type()), list_opc_gen(destroy_opc(), destroy_opc_index()))
    return fun

def destroy_fun_without_split_gen():
    fun = func_gen(destroy_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, destroy_para_type()), list_opc_gen(destroy_opc(), destroy_opc_index()))
    return fun

def split_fun_gen():
    fun = func_gen(split_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, split_para_type()), list_opc_gen(split_opc(), split_opc_index()))
    return fun

def send_fun_gen():
    fun = func_gen(send_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, send_para_type()), list_opc_gen(send_opc(), send_opc_index()))
    return fun

def send_fun_without_split_gen():
    fun = func_gen(send_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, send_para_type()), list_opc_gen(send_opc(), send_opc_index()))
    return fun

def transfer_fun_gen():
    fun = func_gen(transfer_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, transfer_para_type()), list_opc_gen(transfer_opc(), transfer_opc_index()))
    return fun

def transfer_fun_without_split_gen():
    fun = func_gen(transfer_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, transfer_para_type()), list_opc_gen(transfer_opc(), transfer_opc_index()))
    return fun

def deposit_fun_gen():
    fun = func_gen(deposit_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, deposit_para_type()), list_opc_gen(deposit_opc(), deposit_opc_index()))
    return fun

def deposit_fun_without_split_gen():
    fun = func_gen(deposit_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, deposit_para_type()), list_opc_gen(deposit_opc(), deposit_opc_index()))
    return fun

def withdraw_fun_gen():
    fun = func_gen(withdraw_fun_id_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, withdraw_para_type()), list_opc_gen(withdraw_opc(), withdraw_opc_index()))
    return fun

def withdraw_fun_without_split_gen():
    fun = func_gen(withdraw_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen(ContractMeta.non_return_type, withdraw_para_type()), list_opc_gen(withdraw_opc(), withdraw_opc_index()))
    return fun

def total_supply_fun_gen():
    fun = func_gen(total_supply_fun_id_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], total_supply_para_type()), list_opc_gen(total_supply_opc(), total_supply_opc_index()))
    return fun

def total_supply_fun_without_split_gen():
    fun = func_gen(total_supply_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], total_supply_para_type()), list_opc_gen(total_supply_opc(), total_supply_opc_index()))
    return fun

def max_supply_fun_gen():
    fun = func_gen(max_supply_fun_id_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], max_supply_para_type()), list_opc_gen(max_supply_opc(), max_supply_opc_index()))
    return fun

def max_supply_fun_without_split_gen():
    fun = func_gen(max_supply_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], max_supply_para_type()), list_opc_gen(max_supply_opc(), max_supply_opc_index()))
    return fun

def balance_of_fun_gen():
    fun = func_gen(balance_of_fun_id_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], balance_of_para_type()), list_opc_gen(balance_of_opc(), balance_of_opc_index()))
    return fun

def balance_of_fun_without_split_gen():
    fun = func_gen(balance_of_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Amount')], balance_of_para_type()), list_opc_gen(balance_of_opc(), balance_of_opc_index()))
    return fun

def get_issuer_fun_gen():
    fun = func_gen(get_issuer_fun_id_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Account')], get_issuer_para_type()), list_opc_gen(get_issuer_opc(), get_issuer_opc_index()))
    return fun

def get_issuer_fun_without_split_gen():
    fun = func_gen(get_issuer_fun_id_without_split_gen(), function_type_map.get("public"), proto_type_gen([data_type_list.get('Account')], get_issuer_para_type()), list_opc_gen(get_issuer_opc(), get_issuer_opc_index()))
    return fun

def init_fun_id_gen():
    return struct.pack(">H", ContractMeta.init)
def supersede_fun_id_gen():
    return struct.pack(">H", ContractMeta.supersede)
def supersede_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.supersede_without_split)
def issue_fun_id_gen():
    return struct.pack(">H", ContractMeta.issue)
def issue_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.issue_without_split)
def destroy_fun_id_gen():
    return struct.pack(">H", ContractMeta.destroy)
def destroy_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.destroy_without_split)
def split_fun_id_gen():
    return struct.pack(">H", ContractMeta.split)
def send_fun_id_gen():
    return struct.pack(">H", ContractMeta.send)
def send_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.send_without_split)
def transfer_fun_id_gen():
    return struct.pack(">H", ContractMeta.transfer)
def transfer_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.transfer_without_split)
def deposit_fun_id_gen():
    return struct.pack(">H", ContractMeta.deposit)
def deposit_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.deposit_without_split)
def withdraw_fun_id_gen():
    return struct.pack(">H", ContractMeta.withdraw)
def withdraw_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.withdraw_without_split)
def total_supply_fun_id_gen():
    return struct.pack(">H", ContractMeta.total_supply)
def total_supply_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.total_supply_without_split)
def max_supply_fun_id_gen():
    return struct.pack(">H", ContractMeta.max_supply)
def max_supply_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.max_supply_without_split)
def balance_of_fun_id_gen():
    return struct.pack(">H", ContractMeta.balance_of)
def balance_of_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.balance_of_without_split)
def get_issuer_fun_id_gen():
    return struct.pack(">H", ContractMeta.get_issuer)
def get_issuer_fun_id_without_split_gen():
    return struct.pack(">H", ContractMeta.get_issuer_without_split)


def proto_type_gen(return_type, list_para_types):
    proto_type = deser.serialize_array(return_type) + deser.serialize_array(list_para_types)
    return proto_type

def init_para_type_wrong():
    return [data_type_list.get('Amount'), data_type_list.get('Amount')]

def init_para_type():
    return [data_type_list.get('Amount'), data_type_list.get('Amount'), data_type_list.get('ShortText')]

def supersede_para_type():
    return [data_type_list.get('Account')]

def issue_para_type():
    return [data_type_list.get('Amount')]

def destroy_para_type():
    return [data_type_list.get('Amount')]

def split_para_type():
    return [data_type_list.get('Amount')]

def send_para_type():
    return [data_type_list.get('Account'), data_type_list.get('Amount')]

def transfer_para_type():
    return [data_type_list.get('Account'), data_type_list.get('Account'), data_type_list.get('Amount')]

def deposit_para_type():
    return [data_type_list.get('Account'), data_type_list.get('ContractAccount'), data_type_list.get('Amount')]

def withdraw_para_type():
    return [data_type_list.get('ContractAccount'), data_type_list.get('Account'), data_type_list.get('Amount')]

def total_supply_para_type():
    return no_return_bytes

def max_supply_para_type():
    return no_return_bytes

def balance_of_para_type():
    return [data_type_list.get('Account')]

def get_issuer_para_type():
    return no_return_bytes


def list_opc_gen(ids, index_input):
    length = struct.pack(">H", sum(list(map(lambda x: len(x[0]+x[1])+2, list(zip(ids, index_input))))) + 2)
    num_opc = struct.pack(">H", len(ids))
    list_opc = bytes(itertools.chain.from_iterable(list(map(lambda x: struct.pack(">H",len(x[0]+x[1]))+x[0]+x[1], list(zip(ids, index_input))))))
    len_list_opc = length + num_opc + list_opc
    return len_list_opc


def opc_load_signer_index():
    return bytes([3])

def opc_load_caller_index():
    return bytes([2])

def init_opc_cdbv_set_signer_index():
    return ContractMeta.state_var_issuer + ContractMeta.init_input_issuer_load_index

def init_opc_cdbv_set_maker_index():
    return ContractMeta.state_var_maker + ContractMeta.init_input_issuer_load_index

def init_opc_tdb_new_token_index():
    return ContractMeta.init_input_max_index + ContractMeta.init_input_unity_index + ContractMeta.init_input_short_text_index

def init_wrong_tdb_opc():
    return [opc_load_signer(), opc_cdbv_set(), opc_cdbv_set(), bytes([5]), bytes([3])]

def init_opc():
    return [opc_load_signer(), opc_cdbv_set(), opc_cdbv_set(), opc_tdb_new_token()]

def init_opc_index():
    return [opc_load_signer_index(), init_opc_cdbv_set_signer_index(), init_opc_cdbv_set_maker_index(), init_opc_tdb_new_token_index()]

def supersede_opc_cdbvr_get_index():
    return ContractMeta.state_var_maker + bytes([1])

def supersede_assert_is_signer_origin_index():
    return ContractMeta.supersede_input_maker

def supersede_opc_cdbv_set_index():
    return ContractMeta.state_var_issuer + ContractMeta.supersede_input_new_issuer_index

def supersede_opc():
    return [opc_cdbvr_get(), opc_assert_is_signer_origin(), opc_cdbv_set()]

def supersede_opc_index():
    return [supersede_opc_cdbvr_get_index(), supersede_assert_is_signer_origin_index(), supersede_opc_cdbv_set_index()]

def issue_opc_cdbvr_get_index():
    return ContractMeta.state_var_issuer + bytes([1])

def issue_opc_assert_is_caller_origin_index():
    return ContractMeta.issue_input_issuer_get_index

def issue_opc_tdba_deposit_index():
    return ContractMeta.issue_input_issuer_get_index + ContractMeta.issue_input_amount_index

def issue_opc():
    return [opc_cdbvr_get(), opc_assert_is_caller_origin(), opc_tdba_deposit()]

def issue_opc_index():
    return [issue_opc_cdbvr_get_index(), issue_opc_assert_is_caller_origin_index(), issue_opc_tdba_deposit_index()]

def destroy_opc_cdbvr_get_index():
    return ContractMeta.state_var_issuer + bytes([1])

def destroy_opc_assert_is_caller_origin_index():
    return ContractMeta.destroy_input_issuer_get_index

def destroy_opc_tdba_withdraw_index():
    return ContractMeta.destroy_input_issuer_get_index + ContractMeta.destroy_input_destroy_amount_index

def destroy_opc():
    return [opc_cdbvr_get(), opc_assert_is_caller_origin(), opc_tdba_withdraw()]

def destroy_opc_index():
    return [destroy_opc_cdbvr_get_index(), destroy_opc_assert_is_caller_origin_index(), destroy_opc_tdba_withdraw_index()]

def split_opc_cdbvr_get_index():
    return ContractMeta.state_var_issuer + bytes([1])

def split_opc_assert_is_caller_origin_index():
    return ContractMeta.split_input_issuer_get_index

def split_opc_tdb_split_index():
    return ContractMeta.split_input_new_unity_index

def split_opc():
    return [opc_cdbvr_get(), opc_assert_is_caller_origin(), opc_tdb_split()]

def split_opc_index():
    return [split_opc_cdbvr_get_index(), split_opc_assert_is_caller_origin_index(), split_opc_tdb_split_index()]

def send_opc_tdba_transfer_index():
    return ContractMeta.send_input_sender_index + ContractMeta.send_input_recipient_index + ContractMeta.send_input_amount_index

def send_opc():
    return [opc_load_caller(), opc_tdba_transfer()]

def send_opc_index():
    return [opc_load_caller_index(), send_opc_tdba_transfer_index()]

def transfer_opc_assert_is_caller_origin_index():
    return ContractMeta.transfer_input_sender_index

def transfer_opc_tdba_transfer_index():
    return ContractMeta.transfer_input_sender_index + ContractMeta.transfer_input_recipient_index + ContractMeta.transfer_input_amount_index

def transfer_opc():
    return [opc_assert_is_caller_origin(), opc_tdba_transfer()]

def transfer_opc_index():
    return [transfer_opc_assert_is_caller_origin_index(), transfer_opc_tdba_transfer_index()]

def deposit_opc_assert_is_caller_origin_index():
    return ContractMeta.deposit_input_sender_index

def deposit_opc_tdba_transfer_index():
    return ContractMeta.deposit_input_sender_index + ContractMeta.deposit_input_smart_contract_index + ContractMeta.deposit_input_amount_index

def deposit_opc():
    return [opc_assert_is_caller_origin(), opc_tdba_transfer()]

def deposit_opc_index():
    return [deposit_opc_assert_is_caller_origin_index(), deposit_opc_tdba_transfer_index()]

def withdraw_opc_assert_is_caller_origin_index():
    return ContractMeta.withdraw_input_recipient_index

def withdraw_opc_tdba_transfer_index():
    return ContractMeta.withdraw_input_smart_contract_index + ContractMeta.withdraw_input_recipient_index + ContractMeta.withdraw_input_amount_index

def withdraw_opc():
    return [opc_assert_is_caller_origin(), opc_tdba_transfer()]

def withdraw_opc_index():
    return [withdraw_opc_assert_is_caller_origin_index(), withdraw_opc_tdba_transfer_index()]

def total_supply_opc_tdbr_total_index():
    return bytes([0])

def total_supply_opc():
    return [opc_tdbr_opc_total(), opc_return_value()]

def total_supply_opc_index():
    return [total_supply_opc_tdbr_total_index(), bytes([0])]

def max_supply_opc_tdbr_max_index():
    return bytes([0])

def max_supply_opc():
    return [opc_tdbr_opc_max(), opc_return_value()]

def max_supply_opc_index():
    return [max_supply_opc_tdbr_max_index(), bytes([0])]

def balance_of_opc_tdbar_balance_index():
    return ContractMeta.balance_of_input_account_index + bytes([1])

def balance_of_opc():
    return [opc_tdbar_balance(), opc_return_value()]

def balance_of_opc_index():
    return [balance_of_opc_tdbar_balance_index(), bytes([1])]

def get_issuer_opc_cdbvr_get_index():
    return ContractMeta.state_var_issuer + bytes([0])

def get_issuer_opc():
    return [opc_cdbvr_get(), opc_return_value()]

def get_issuer_opc_index():
    return [get_issuer_opc_cdbvr_get_index(), bytes([0])]


class ContractDefaults:
    trigger = bytes_builder_from_list([init_fun_gen()])

    descriptor_without_split = bytes_builder_from_list(
        [supersede_fun_without_split_gen(), issue_fun_without_split_gen(),
         destroy_fun_without_split_gen(),
         send_fun_without_split_gen(), transfer_fun_without_split_gen(),
         deposit_fun_without_split_gen(), withdraw_fun_without_split_gen(),
         total_supply_fun_without_split_gen(),
         max_supply_fun_without_split_gen(), balance_of_fun_without_split_gen(),
         get_issuer_fun_without_split_gen()])

    descriptor_with_split = bytes_builder_from_list(
        [supersede_fun_gen(), issue_fun_gen(), destroy_fun_gen(), split_fun_gen(),
         send_fun_gen(),
         transfer_fun_gen(), deposit_fun_gen(), withdraw_fun_gen(), total_supply_fun_gen(),
         max_supply_fun_gen(), balance_of_fun_gen(), get_issuer_fun_gen()])

    state_var = bytes_builder_from_list([ContractMeta.state_var_issuer + data_type_list.get('Address'), ContractMeta.state_var_maker + data_type_list.get('Address')])

    state_var_textual = deser.serialize_arrays([deser.serialize_string(name) for name in ContractMeta.state_var_name])
    initializer_textual = deser.serialize_arrays([init_func_bytes()])

    descriptor_textual_without_split = deser.serialize_arrays([supersede_func_bytes(),
                                                      issue_func_bytes(),
                                                      destroy_func_bytes(),
                                                      send_func_bytes(),
                                                      transfer_func_bytes(),
                                                      deposit_func_bytes(),
                                                      withdraw_func_bytes(),
                                                      total_supply_func_bytes(),
                                                      max_supply_func_bytes(),
                                                      balance_of_func_bytes(),
                                                      get_issuer_func_bytes()])

    descriptor_textual_with_split = deser.serialize_arrays([supersede_func_bytes(),
                                                      issue_func_bytes(),
                                                      destroy_func_bytes(),
                                                      split_func_bytes(),
                                                      send_func_bytes(),
                                                      transfer_func_bytes(),
                                                      deposit_func_bytes(),
                                                      withdraw_func_bytes(),
                                                      total_supply_func_bytes(),
                                                      max_supply_func_bytes(),
                                                      balance_of_func_bytes(),
                                                      get_issuer_func_bytes()])

    textual_without_split = deser.serialize_arrays([initializer_textual, descriptor_textual_without_split, state_var_textual])
    textual_with_split = deser.serialize_arrays(
        [initializer_textual, descriptor_textual_with_split, state_var_textual])
