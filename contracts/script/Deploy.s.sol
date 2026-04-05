// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/ResqdCanaryAnchor.sol";

/// @notice Deploys ResqdCanaryAnchor. Use --broadcast to actually deploy.
/// @dev Env vars:
///   - PRIVATE_KEY: deployer key (will become owner + first authorized signer)
///   - RPC target: --rpc-url base_sepolia | base
contract DeployScript is Script {
    function run() external returns (ResqdCanaryAnchor deployed) {
        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPk);
        deployed = new ResqdCanaryAnchor();
        vm.stopBroadcast();
        console.log("ResqdCanaryAnchor deployed at:", address(deployed));
    }
}
