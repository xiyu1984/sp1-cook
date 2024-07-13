// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";

/// @title Fibonacci.
/// @author Succinct Labs
/// @notice This contract implements a simple example of verifying the proof of a computing a
///         fibonacci number.
contract AnyVerifier is SP1Verifier {
    /// @notice The verification key for the fibonacci program.
    bytes32 public any_vkey_hash;

    constructor(bytes32 _any_vkey_hash) {
        any_vkey_hash = _any_vkey_hash;
    }

    /// @notice The entrypoint for verifying the proof of a fibonacci number.
    /// @param proof The encoded proof.
    function verifyAnyProof(bytes memory proof, bytes memory publicValues) public view {
        this.verifyProof(any_vkey_hash, publicValues, proof);
    }
}