// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "dependencies/tnt-core-0.1.0/src/BlueprintServiceManagerBase.sol";

/**
 * @title WstsBlueprint
 * @dev This contract is an example of a service blueprint that provides a single service.
 * @dev For all supported hooks, check the `BlueprintServiceManagerBase` contract.
 */
contract WstsBlueprint is BlueprintServiceManagerBase {
    function operatorAddressFromPublicKey(bytes calldata publicKey) internal pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }
}
