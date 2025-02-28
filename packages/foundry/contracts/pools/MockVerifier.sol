//SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IHalo2Verifier } from "./IHalo2Verifier.sol";

contract MockVerifier is IHalo2Verifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external returns (bool)  {
        return true;
    }
}