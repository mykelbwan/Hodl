-include .env

t:; forge test #test
cln:; forge clean #clean
t-a-dep: #test anvil deploy
	forge script script/DeployHodlTestFile.s.sol:DeployHodl --rpc-url $(ANVIL_RPC) --private-key $(A_KEY) --broadcast

a-dep: #anvil-deploy (just being a lil bit lazy than some mfrs out there)
	forge script script/DeployHodlMain.s.sol:DeployHodl --rpc-url $(ANVIL_RPC) --private-key $(A_KEY) --broadcast

s-dep: #sepolia deploy
	forge script script/DeployHodlMain.s.sol:DeployHodl --rpc-url $(S_URL) --private-key $(T_KEY) --broadcast --verify --etherscan-api-key $(ETHERSCAN_KEY) -vvv

cvg:; forge coverage ## coverage

fmt:; forge fmt #format

cl:; forge compile #compile

bld:; forge build # build