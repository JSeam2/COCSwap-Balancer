//SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IHalo2Verifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external returns (bool) 
}