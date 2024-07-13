// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {AnyVerifier} from "../src/anyverifier.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";

struct AnyProofFixtureJson {
    bytes proof;
    bytes publicValues;
    bytes32 vkey_hash;
}

contract Eip712Test is Test {
    using stdJson for string;

    AnyVerifier public any_verifier;

    function loadFixture() public view returns (AnyProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/eip712-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (AnyProofFixtureJson));
    }

    function setUp() public {
        AnyProofFixtureJson memory fixture = loadFixture();
        any_verifier = new AnyVerifier(fixture.vkey_hash);
    }

    function test_ValidEcRecoverProof() public view {
        AnyProofFixtureJson memory fixture = loadFixture();
        any_verifier.verifyAnyProof(
            fixture.proof, fixture.publicValues
        );
    }

    function testFail_InvalidEcRecoverProof() public view {
        AnyProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        any_verifier.verifyAnyProof(fakeProof, fixture.publicValues);
    }
}
