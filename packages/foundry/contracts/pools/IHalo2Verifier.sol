//SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Halo2Verifier from ezkl
 * @notice This is the Halo2Verifier from the ezkl library
 * You will need to obtain the PK (proving key) in order to generate the proof and instances
 */
interface IHalo2Verifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external returns (bool);
}