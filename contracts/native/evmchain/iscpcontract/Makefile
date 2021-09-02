all: ISCP.bin-runtime ISCPYul.bin-runtime

ARGS=--evm-version=homestead

# TODO: solc --pretty-json does not work as advertised?

# also produces ISCP.abi
ISCP.bin-runtime: iscp.sol
	solc --abi --bin-runtime --overwrite $(ARGS) iscp.sol -o .

ISCPYul.bin-runtime: iscp.yul
	solc --strict-assembly iscp.yul | awk '/Binary representation:/ { getline; print $0 }' > ISCPYul.bin-runtime

# call `make storage-layout | jq .` for pretty printed json
storage-layout:
	@solc --storage-layout $(ARGS) iscp.sol | tail -n +4

.PHONY: storage-layout
