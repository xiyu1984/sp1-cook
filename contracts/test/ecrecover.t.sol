// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {EcRecover} from "../src/ecrecover.sol";
import {SP1Verifier} from "@sp1-contracts/SP1Verifier.sol";

struct EcRecoverProofFixtureJson {
    bytes proof;
    bytes publicValues;
    bytes32 vkey_hash;
}

contract EcRecoverTest is Test {
    using stdJson for string;

    EcRecover public ec_recover;

    function loadFixture() public view returns (EcRecoverProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/src/fixtures/ecr-fixture.json");
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (EcRecoverProofFixtureJson));
    }

    function setUp() public {
        EcRecoverProofFixtureJson memory fixture = loadFixture();
        ec_recover = new EcRecover(fixture.vkey_hash);
    }

    function test_ValidEcRecoverProof() public view {
        EcRecoverProofFixtureJson memory fixture = loadFixture();
        ec_recover.verifyEcRecoverProof(
            fixture.proof, fixture.publicValues
        );
    }

    function testFail_InvalidEcRecoverProof() public view {
        EcRecoverProofFixtureJson memory fixture = loadFixture();

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        ec_recover.verifyEcRecoverProof(fakeProof, fixture.publicValues);
    }
}
