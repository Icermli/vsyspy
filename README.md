# VSYSPY
A python wrapper for vsys api.

## Install

### Install source code
1. clone the repo under you workspace
```shell script
git clone https://github.com/Icermli/vsyspy.git
```
2. install packages in vsyspy/requirement.txt by 
```shell script
cd vsyspy
pip install .
```
Or, for developers, you may want to install the package with a symlink,
```shell script
pip install -e .
```
3. Then you can ```import vsyspy``` in your workspace

### Install via PyPi
```shell script
pip install vsyspy
```

## Usage

### chain object
1. For testnet:
```python
import vsyspy as vpy
ts_chain = vpy.testnet_chain()
```
2. For default chain:
```python
import vsyspy as vpy
main_chain = vpy.default_chain()
```

3. For custom api node:
```python
import vsyspy as vpy
custom_wrapper = vpy.create_api_wrapper('http://<full node ip>:9922', api_key='')
ts_chain = vpy.testnet_chain(custom_wrapper)
```

4. For completely custom chain:
```python
import vsyspy as vpy
custom_wrapper = vpy.create_api_wrapper('http://<full node ip>:9922', api_key='')
t_chain = vpy.Chain(chain_name='testnet', chain_id='T', address_version=5, api_wrapper=custom_wrapper)
custom_wrapper2 = vpy.create_api_wrapper('http://<full node ip>:9922', api_key='')
m_chain = vpy.Chain(chain_name='mainnet', chain_id='M', address_version=5, api_wrapper=custom_wrapper2)
custom_wrapper3 = vpy.create_api_wrapper('http://<full node ip>:9922', api_key='')
c_chain = vpy.Chain(chain_name='mychain', chain_id='C', address_version=1, api_wrapper=custom_wrapper3)
```

### chain api list
1. look up current block height of the chain:
```python
ts_chain.height()
```
2. look up the last block info of the chain:
```python
ts_chain.lastblock()
```
3. look up a block info at n in the chain:
```python
ts_chain.block(n)
```
4. Get a transaction info by transacion id in the chain:
```python
ts_chain.tx(tx_id)
```
5. Validate an address of the chain:
```python
ts_chain.validate_address(addr)
```

### address object
1. constructed by seed
```python
from vsyspy import Account
my_address = Account(chain=ts_chain, seed='<your seed>', nonce=0)
```
2. constructed by private key
```python
from vsyspy import Account
my_address = Account(chain=ts_chain, private_key='<your base58 private key>')
```
3. constructed by public key
```python
from vsyspy import Account
recipient = Account(chain=ts_chain, public_key='<base58 public key>')
```
4. constructed by wallet address
```python
from vsyspy import Account
recipient = Account(chain=ts_chain, address='<base58 wallet address>')
```
 
### address api list
1. Get balance
```python
# get balance
balance = my_address.balance()
print("The balance is {}".format(balance))
# get balance after 16 confirmations 
balance = my_address.balance(confirmations = 16)
print("The balance is {}".format(balance))
```
2. Send payment transaction
```python
# send payment (100000000 = 1 VSYS)
my_address.send_payment(recipient, amount=100000000)
```
3. Send and cancel lease transaction
```python
# send lease (100000000 = 1 VSYS)
response = my_address.lease(recipient, amount=100000000)
tx_id = response["id"]
# cancel lease
my_address.lease_cancel(tx_id)
```
    
### contract object
1. Register contract
```python
from vsyspy import DataEntry
from vsyspy.contract import Type
# register contract of max 1000000000000 and unit 1000000
maximum = DataEntry(1000000000000, Type.amount)
unit = DataEntry(1000000, Type.amount)
short_txt = DataEntry('', Type.short_text)
init_data_stack = [maximum, unit, short_txt]
response = my_address.register_contract('<contract-string>', init_data_stack)
contract_id = response["contractId"]
```
2. Execute contract
```python
# execute issue function of 1000000000 tokens
amount = DataEntry(1000000000, Type.amount)
issue_data_stack = [amount]
my_address.execute_contract(contract_id, 1, issue_data_stack)
```
