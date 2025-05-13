// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHalo2Verifier} from "../utils/IHalo2Verifier.sol";

contract SUSDDynamicFeeVerifier is IHalo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x09a4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0aa4;

    uint256 internal constant                VK_MPTR = 0x05a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x05a0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x05c0;
    uint256 internal constant                 K_MPTR = 0x05e0;
    uint256 internal constant             N_INV_MPTR = 0x0600;
    uint256 internal constant             OMEGA_MPTR = 0x0620;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0640;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0660;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0680;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x06a0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x06c0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x06e0;
    uint256 internal constant              G1_X_MPTR = 0x0700;
    uint256 internal constant              G1_Y_MPTR = 0x0720;
    uint256 internal constant            G2_X_1_MPTR = 0x0740;
    uint256 internal constant            G2_X_2_MPTR = 0x0760;
    uint256 internal constant            G2_Y_1_MPTR = 0x0780;
    uint256 internal constant            G2_Y_2_MPTR = 0x07a0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x07c0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x07e0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0800;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0820;

    uint256 internal constant CHALLENGE_MPTR = 0x1080;

    uint256 internal constant THETA_MPTR = 0x1080;
    uint256 internal constant  BETA_MPTR = 0x10a0;
    uint256 internal constant GAMMA_MPTR = 0x10c0;
    uint256 internal constant     Y_MPTR = 0x10e0;
    uint256 internal constant     X_MPTR = 0x1100;
    uint256 internal constant  ZETA_MPTR = 0x1120;
    uint256 internal constant    NU_MPTR = 0x1140;
    uint256 internal constant    MU_MPTR = 0x1160;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1180;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x11a0;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x11c0;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x11e0;
    uint256 internal constant             X_N_MPTR = 0x1200;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x1220;
    uint256 internal constant          L_LAST_MPTR = 0x1240;
    uint256 internal constant         L_BLIND_MPTR = 0x1260;
    uint256 internal constant             L_0_MPTR = 0x1280;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x12a0;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x12c0;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x12e0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1300;
    uint256 internal constant          R_EVAL_MPTR = 0x1320;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1340;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1360;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1380;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x13a0;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field 

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x05a0, 0x206b040a637065cc3b54d01c62494b3fa04f48fbc87f5d386e1378157027aac6) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000152) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1600, proof.length))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, instances.length))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := instances.offset
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := proof.offset
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0240) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0300) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0400) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0b00) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x05a0, 0x206b040a637065cc3b54d01c62494b3fa04f48fbc87f5d386e1378157027aac6) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000152) // num_instances
                mstore(0x05e0, 0x0000000000000000000000000000000000000000000000000000000000000015) // k
                mstore(0x0600, 0x30644cefbebe09202b4ef7f3ff53a4511d70ff06da772cc3785d6b74e0536081) // n_inv
                mstore(0x0620, 0x032750f8f3c2493d0828c7285d0258e1bdcaa463f4442a52747b5c96639659bb) // omega
                mstore(0x0640, 0x06288b9d40ec1915c3a20817de7179beeccf4c4fd02f202c064a0cc13e38c2f8) // omega_inv
                mstore(0x0660, 0x0118444755e4129457b85d47760f652dd3c81fbdec5ea1924ff46796b5299545) // omega_inv_to_l
                mstore(0x0680, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x06a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x06c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0720, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0740, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0760, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0780, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x07a0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x07c0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x07e0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x0800, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0820, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0840, 0x0e9911529fae6d39405db2a3a4d5dc8768b0c479cb4df99b8ba7b8ef8f2ed951) // fixed_comms[0].x
                mstore(0x0860, 0x0ddfab126258b5bfd416edd9da4c0b64ebc4b3013e06b6f49fb1c25d6a0f7619) // fixed_comms[0].y
                mstore(0x0880, 0x2fda0b2d2f39d13059062c96005f807c58179000bd398ca449d67e2a14fa00d8) // fixed_comms[1].x
                mstore(0x08a0, 0x13c7b941ed3650a4e27a621d61530109286aba50f56135971236d8f658d683a0) // fixed_comms[1].y
                mstore(0x08c0, 0x1c947441a2b8aff70f81184cd6e97994463f113fde84401766fa8adfbb42b103) // fixed_comms[2].x
                mstore(0x08e0, 0x29cb368f369dbe0efb0da475f1e62eef4928c7d8a63ae4db447ae0dc6b9382f4) // fixed_comms[2].y
                mstore(0x0900, 0x28c95b26dd806f8f3f736d585ba8be05721d36f54dddeac0a6d07d6a03e442e8) // fixed_comms[3].x
                mstore(0x0920, 0x0ed0e303ed5c56f4c9359d868b9e290c47c43f637fc64d3936ef04df91f45051) // fixed_comms[3].y
                mstore(0x0940, 0x29b212d10b64d0a91cfa7c394382ae076663ff8860dc59aadd796d22542fb06c) // fixed_comms[4].x
                mstore(0x0960, 0x00f541abef84cb47c0054ca19a5e9341e3984383095acb66c4b90e2a312a9943) // fixed_comms[4].y
                mstore(0x0980, 0x0f8954a32ad77721facf286a065d539b4fd12a018a381b2c1cc91891e8938fe3) // fixed_comms[5].x
                mstore(0x09a0, 0x1a99afd5c93b25dd88ba61351142049b7fc834a50758664fb7cb2838797e8cf7) // fixed_comms[5].y
                mstore(0x09c0, 0x119621d5e7b862a686091e69665e72afd0347081bae32ae9966ace98711ef52c) // fixed_comms[6].x
                mstore(0x09e0, 0x0e17c8703d7659928be059cdae6570bf7ae9250ee9b6276a7b51349d2d015884) // fixed_comms[6].y
                mstore(0x0a00, 0x17b5fd961e52e398c6ada793e8d9d0bc2edf043122386ff51a84a7029b298f2c) // fixed_comms[7].x
                mstore(0x0a20, 0x2f17ee7895c413b22432065d2bc0ae8d63d90f7df819f348956eb07827be1103) // fixed_comms[7].y
                mstore(0x0a40, 0x2e5ac41429887a2492b2e3d0b45c9de262f28ff3e2217d285c3d6f4d163f1286) // fixed_comms[8].x
                mstore(0x0a60, 0x12d92f4b787eacc80eab8735aae300fe5701ec6f7ff4a749cc0edb6c6cc3f412) // fixed_comms[8].y
                mstore(0x0a80, 0x0d0a742fa6f47191815450f9bfa967ba2f885b48ce367a68c2dd5f614b82cfcb) // fixed_comms[9].x
                mstore(0x0aa0, 0x29a80f4dfbf7c50c37ce51c6cc36f1283bde281a7d79ae51a9bef8db3af20057) // fixed_comms[9].y
                mstore(0x0ac0, 0x07adb2e6525924156fdc49d027c6898537ab0bf488d9745ef8bbab22f72ebc91) // fixed_comms[10].x
                mstore(0x0ae0, 0x14e0dd8f40f1935e0bb762b2554f2c2b376c567f87586df1b940d340a6aae5fd) // fixed_comms[10].y
                mstore(0x0b00, 0x23b64fcce4ecb4e7dc2147de7e01eb337a01e1d789e5ccf9fef2c35d6f072072) // fixed_comms[11].x
                mstore(0x0b20, 0x164b1a3dac10aee6b72c3bae42b5105db18a3cd4930d7c26d2e616afd8ce0836) // fixed_comms[11].y
                mstore(0x0b40, 0x2fc754339f980b6cc997a26a02a718c59b9fbd1f9ad06109f6c8ba37f161a48e) // fixed_comms[12].x
                mstore(0x0b60, 0x227f0d9af0f8e00d060d368a25f80a6948554e591ab2a6dab1a1f6f4e5477792) // fixed_comms[12].y
                mstore(0x0b80, 0x1831deff07ff0e6f9bc1479ac0ef6bf4ddd99286335146f4e0a3d3974db1b941) // fixed_comms[13].x
                mstore(0x0ba0, 0x0faa5b76c79fd844b55da76c783a2fcdd9261ab361c60cc28246e58597a333a5) // fixed_comms[13].y
                mstore(0x0bc0, 0x10938d0afc3143e2c87ee177b58f7c4e7079d5eb5b1fe5e494b43f0ffdff5534) // fixed_comms[14].x
                mstore(0x0be0, 0x1af6d47f33c75fa35de825b974344eb66e05ee29b3d29f03822e5138b9080808) // fixed_comms[14].y
                mstore(0x0c00, 0x073ad1b94c98535525505f165ecf17adbceb459dd59f0542b0cc673330ab38ca) // fixed_comms[15].x
                mstore(0x0c20, 0x1456596a6e908d630ad94cb770496aec410062f63dad66076a6acc069e7aa7c3) // fixed_comms[15].y
                mstore(0x0c40, 0x033fc61048d2bec39452c48409e3d2f11fcd44cde4e943847f263a9f8b0ba49b) // fixed_comms[16].x
                mstore(0x0c60, 0x1000173f31c3d63b397552565cd51e77441624efc9bd47d89ee8fe3c7c21fb88) // fixed_comms[16].y
                mstore(0x0c80, 0x033fc61048d2bec39452c48409e3d2f11fcd44cde4e943847f263a9f8b0ba49b) // fixed_comms[17].x
                mstore(0x0ca0, 0x1000173f31c3d63b397552565cd51e77441624efc9bd47d89ee8fe3c7c21fb88) // fixed_comms[17].y
                mstore(0x0cc0, 0x07d529debd0769942d64e926571506fa4ae6331304b321c07307e1bc1d160c13) // fixed_comms[18].x
                mstore(0x0ce0, 0x19f2a9b5c03f44e546b5e7631850a57a1f2ad90cb3ffa8c4cd111d16fa6761a1) // fixed_comms[18].y
                mstore(0x0d00, 0x238f36c2a38291fb746398fb6ce92d59fc02b7e3d1fb913ce505f8840da64670) // fixed_comms[19].x
                mstore(0x0d20, 0x25d7e07cd0d06ddb0fae61f418d353b2fcbbdfb47ced5a378a22383cb904c3b3) // fixed_comms[19].y
                mstore(0x0d40, 0x139aa162d594a774ca3904f6ee562256f699c500e1833f2e8dd8639768b8f7b3) // fixed_comms[20].x
                mstore(0x0d60, 0x07f5a92c2eb0deca2c7f2209703be73c73b68fc1a9c3a378cd55cf9783afc109) // fixed_comms[20].y
                mstore(0x0d80, 0x2241490ab9b568d849d9d2b7d7a9766f10a46ca09205e3cb32c9b574aa55cfe7) // fixed_comms[21].x
                mstore(0x0da0, 0x22983544886fed6dcc86be1e2dc3e468db55fea68d1c6082733e428d325089be) // fixed_comms[21].y
                mstore(0x0dc0, 0x253d748a06a0f27419419a72e88be376045dd3bebdc97a66fed083ba37d605cc) // permutation_comms[0].x
                mstore(0x0de0, 0x1642c513564d002ce121125b534dd5377cb7e41a6257e826e1ebf79bdfde7617) // permutation_comms[0].y
                mstore(0x0e00, 0x1cd8feca9a89d0c6572935658cc21cb53724807f3a4076bf87295e213214b5a4) // permutation_comms[1].x
                mstore(0x0e20, 0x166e1d52ff37f2e6f037e5d8d9880e1620bc96f5ad1369d5c59a8133552123b0) // permutation_comms[1].y
                mstore(0x0e40, 0x208c5088c426f9a964d2a6ece352e151a06ed0d02871b11d7b7f84705d583ab1) // permutation_comms[2].x
                mstore(0x0e60, 0x17b5235fe73dbdfab8cba9641cbde6659790a9b821420c4d78fe35ab4e67e4f2) // permutation_comms[2].y
                mstore(0x0e80, 0x05975a0cd73a777105e8d45bfd37b7433c369df8e91b299b978b1cad41d5c01e) // permutation_comms[3].x
                mstore(0x0ea0, 0x038a8f5d03cbc3c9c42e752c6e04e6f78511944dd95203fed2de38b611a95e3c) // permutation_comms[3].y
                mstore(0x0ec0, 0x2d2149a5668a2b968e9e4687eccda388f17d09954c578f7f4fe8212f96b2ed9f) // permutation_comms[4].x
                mstore(0x0ee0, 0x114926f39e7f9c63ab5df2d7cea10e8cca360b23e0f98f298be28e95282ff953) // permutation_comms[4].y
                mstore(0x0f00, 0x0dc290c2ad5447111cab9fc8287d7e09fb023b026f163922035fea26ec0b0037) // permutation_comms[5].x
                mstore(0x0f20, 0x224ceca6d07c73bbba032730a4cd618995d4e93615a8e35aaea7d1b415b07168) // permutation_comms[5].y
                mstore(0x0f40, 0x0ba46dab75200d10cda938d452c30a9298658ff2ab7512ce4196c4c4bde2f838) // permutation_comms[6].x
                mstore(0x0f60, 0x01db708215b4d2847389074901f4488b55e516f8fe8494d971f40164907afe70) // permutation_comms[6].y
                mstore(0x0f80, 0x16f354cde8143b6498411037003949980f16ad74d452129f1a7e9215775ba888) // permutation_comms[7].x
                mstore(0x0fa0, 0x25bf3d9b9ed4f9d853d1f5103238b4ccb97a0ec20176a49a683fee8dcd5e3f57) // permutation_comms[7].y
                mstore(0x0fc0, 0x01a7837e6470babb230978a3079af34e382588caaf1c0c791e81f37222798929) // permutation_comms[8].x
                mstore(0x0fe0, 0x155c9bea95acf37b018196229c82254163940010ab902b96a4dcde67c6a99a6f) // permutation_comms[8].y
                mstore(0x1000, 0x2e7068bd84af367a1787445bde43fb2bd63846f2675f5116bcc8fc04bc2d6821) // permutation_comms[9].x
                mstore(0x1020, 0x1467be43d0f486e1890c0d061aef100711b70356fa22eebeb4ed3561a333f271) // permutation_comms[9].y
                mstore(0x1040, 0x16f2296cdde5dde6d16f78240d4ef1d2086034226c9d9b74d9c2d487a7296bce) // permutation_comms[10].x
                mstore(0x1060, 0x2e68ffd6c0cc9e36b2043cbaaa727d4d9bee1b217e90553e3ab6e8643c5977fa) // permutation_comms[10].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(instances.offset, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := instances.offset
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_18 := calldataload(0x0e64)
                    let var0 := 0x2
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_4 := calldataload(0x0b64)
                    let a_0 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0b24)
                    let var10 := addmod(a_0, a_2, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_4, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := var13
                }
                {
                    let f_19 := calldataload(0x0e84)
                    let var0 := 0x2
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_5 := calldataload(0x0b84)
                    let a_1 := calldataload(0x0b04)
                    let a_3 := calldataload(0x0b44)
                    let var10 := addmod(a_1, a_3, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_5, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_18 := calldataload(0x0e64)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_4 := calldataload(0x0b64)
                    let a_0 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0b24)
                    let var10 := mulmod(a_0, a_2, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_4, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_19 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_5 := calldataload(0x0b84)
                    let a_1 := calldataload(0x0b04)
                    let a_3 := calldataload(0x0b44)
                    let var10 := mulmod(a_1, a_3, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_5, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_18 := calldataload(0x0e64)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_4 := calldataload(0x0b64)
                    let a_0 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0b24)
                    let var10 := sub(R, a_2)
                    let var11 := addmod(a_0, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_4, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_19 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_5 := calldataload(0x0b84)
                    let a_1 := calldataload(0x0b04)
                    let a_3 := calldataload(0x0b44)
                    let var10 := sub(R, a_3)
                    let var11 := addmod(a_1, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_5, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_19 := calldataload(0x0e84)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_4 := calldataload(0x0b64)
                    let a_4_prev_1 := calldataload(0x0c04)
                    let var10 := 0x0
                    let a_0 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0b24)
                    let var11 := mulmod(a_0, a_2, R)
                    let var12 := addmod(var10, var11, R)
                    let a_1 := calldataload(0x0b04)
                    let a_3 := calldataload(0x0b44)
                    let var13 := mulmod(a_1, a_3, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := addmod(a_4_prev_1, var14, R)
                    let var16 := sub(R, var15)
                    let var17 := addmod(a_4, var16, R)
                    let var18 := mulmod(var9, var17, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_18 := calldataload(0x0e64)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_4 := calldataload(0x0b64)
                    let var10 := 0x0
                    let a_0 := calldataload(0x0ae4)
                    let a_2 := calldataload(0x0b24)
                    let var11 := mulmod(a_0, a_2, R)
                    let var12 := addmod(var10, var11, R)
                    let a_1 := calldataload(0x0b04)
                    let a_3 := calldataload(0x0b44)
                    let var13 := mulmod(a_1, a_3, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_4, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_20 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0b64)
                    let a_2 := calldataload(0x0b24)
                    let var7 := mulmod(var0, a_2, R)
                    let a_3 := calldataload(0x0b44)
                    let var8 := mulmod(var7, a_3, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_4, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_20 := calldataload(0x0ea4)
                    let var0 := 0x2
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0b64)
                    let a_4_prev_1 := calldataload(0x0c04)
                    let var7 := 0x1
                    let a_2 := calldataload(0x0b24)
                    let var8 := mulmod(var7, a_2, R)
                    let a_3 := calldataload(0x0b44)
                    let var9 := mulmod(var8, a_3, R)
                    let var10 := mulmod(a_4_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_4, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_21 := calldataload(0x0ec4)
                    let a_4 := calldataload(0x0b64)
                    let var0 := 0x0
                    let a_2 := calldataload(0x0b24)
                    let var1 := addmod(var0, a_2, R)
                    let a_3 := calldataload(0x0b44)
                    let var2 := addmod(var1, a_3, R)
                    let var3 := sub(R, var2)
                    let var4 := addmod(a_4, var3, R)
                    let var5 := mulmod(f_21, var4, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var5, r)
                }
                {
                    let f_20 := calldataload(0x0ea4)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_4 := calldataload(0x0b64)
                    let a_4_prev_1 := calldataload(0x0c04)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0b24)
                    let var8 := addmod(var7, a_2, R)
                    let a_3 := calldataload(0x0b44)
                    let var9 := addmod(var8, a_3, R)
                    let var10 := addmod(a_4_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_4, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_7 := calldataload(0x0d04)
                    let var0 := 0x0
                    let var1 := mulmod(f_7, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_8 := calldataload(0x0d24)
                    let var0 := 0x0
                    let var1 := mulmod(f_8, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_9 := calldataload(0x0d44)
                    let var0 := 0x0
                    let var1 := mulmod(f_9, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_10 := calldataload(0x0d64)
                    let var0 := 0x0
                    let var1 := mulmod(f_10, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_11 := calldataload(0x0d84)
                    let var0 := 0x1
                    let a_2 := calldataload(0x0b24)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_2, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_2, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := mulmod(f_11, var7, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_12 := calldataload(0x0da4)
                    let var0 := 0x1
                    let a_3 := calldataload(0x0b44)
                    let var1 := 0x0
                    let var2 := sub(R, var1)
                    let var3 := addmod(a_3, var2, R)
                    let var4 := mulmod(var0, var3, R)
                    let var5 := sub(R, var0)
                    let var6 := addmod(a_3, var5, R)
                    let var7 := mulmod(var4, var6, R)
                    let var8 := mulmod(f_12, var7, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_13 := calldataload(0x0dc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_13, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_14 := calldataload(0x0de4)
                    let var0 := 0x0
                    let var1 := mulmod(f_14, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x1064), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x1124)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x10c4), sub(R, calldataload(0x10a4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1124), sub(R, calldataload(0x1104)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1084)
                    let rhs := calldataload(0x1064)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ae4), mulmod(beta, calldataload(0x0f04), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b04), mulmod(beta, calldataload(0x0f24), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b24), mulmod(beta, calldataload(0x0f44), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b44), mulmod(beta, calldataload(0x0f64), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ae4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x10e4)
                    let rhs := calldataload(0x10c4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b64), mulmod(beta, calldataload(0x0f84), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0b84), mulmod(beta, calldataload(0x0fa4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ba4), mulmod(beta, calldataload(0x0fc4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0bc4), mulmod(beta, calldataload(0x0fe4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0b84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ba4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0bc4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1144)
                    let rhs := calldataload(0x1124)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0be4), mulmod(beta, calldataload(0x1004), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c24), mulmod(beta, calldataload(0x1024), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x1044), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0be4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1164), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1164), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_15 := calldataload(0x0e04)
                        let var1 := mulmod(var0, f_15, R)
                        let a_6 := calldataload(0x0ba4)
                        let var2 := mulmod(a_6, f_15, R)
                        let a_7 := calldataload(0x0bc4)
                        let var3 := mulmod(a_7, f_15, R)
                        let a_8 := calldataload(0x0be4)
                        let var4 := mulmod(a_8, f_15, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_16 := calldataload(0x0e24)
                        let var1 := mulmod(var0, f_16, R)
                        let a_0 := calldataload(0x0ae4)
                        let var2 := mulmod(a_0, f_16, R)
                        let a_2 := calldataload(0x0b24)
                        let var3 := mulmod(a_2, f_16, R)
                        let a_4 := calldataload(0x0b64)
                        let var4 := mulmod(a_4, f_16, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x11a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1184), sub(R, calldataload(0x1164)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x11c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x11c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let var0 := 0x1
                        let f_15 := calldataload(0x0e04)
                        let var1 := mulmod(var0, f_15, R)
                        let a_6 := calldataload(0x0ba4)
                        let var2 := mulmod(a_6, f_15, R)
                        let a_7 := calldataload(0x0bc4)
                        let var3 := mulmod(a_7, f_15, R)
                        let a_8 := calldataload(0x0be4)
                        let var4 := mulmod(a_8, f_15, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_17 := calldataload(0x0e44)
                        let var1 := mulmod(var0, f_17, R)
                        let a_1 := calldataload(0x0b04)
                        let var2 := mulmod(a_1, f_17, R)
                        let a_3 := calldataload(0x0b44)
                        let var3 := mulmod(a_3, f_17, R)
                        let a_5 := calldataload(0x0b84)
                        let var4 := mulmod(a_5, f_17, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1204), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x11e4), sub(R, calldataload(0x11c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1224), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1224), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0c44)
                        let f_2 := calldataload(0x0c64)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0d04)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, R)
                        let a_0 := calldataload(0x0ae4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff01
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_4 := calldataload(0x0b64)
                        let var8 := mulmod(var1, a_4, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1264), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1244), sub(R, calldataload(0x1224)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1284), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1284), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0c44)
                        let f_2 := calldataload(0x0c64)
                        table := f_1
                        table := addmod(mulmod(table, theta, R), f_2, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0d24)
                        let var0 := 0x1
                        let var1 := mulmod(f_8, var0, R)
                        let a_1 := calldataload(0x0b04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff01
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        let a_5 := calldataload(0x0b84)
                        let var8 := mulmod(var1, a_5, R)
                        let var9 := 0x0
                        let var10 := mulmod(var4, var9, R)
                        let var11 := addmod(var8, var10, R)
                        input_0 := var7
                        input_0 := addmod(mulmod(input_0, theta, R), var11, R)
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x12c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x12a4), sub(R, calldataload(0x1284)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x12e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x12e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0c84)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x0d44)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_0 := calldataload(0x0ae4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1324), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1304), sub(R, calldataload(0x12e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1344), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1344), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0c84)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_10 := calldataload(0x0d64)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_1 := calldataload(0x0b04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1384), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1364), sub(R, calldataload(0x1344)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x13a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x13a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0ca4)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_11 := calldataload(0x0d84)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b24)
                        let var1 := sub(R, a_2)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(f_11, var4, R)
                        let a_0 := calldataload(0x0ae4)
                        let var6 := mulmod(var5, a_0, R)
                        let var7 := sub(R, var5)
                        let var8 := addmod(var0, var7, R)
                        let var9 := 0x0
                        let var10 := mulmod(var8, var9, R)
                        let var11 := addmod(var6, var10, R)
                        input_0 := var11
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x13e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x13c4), sub(R, calldataload(0x13a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1404), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1404), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_4 := calldataload(0x0ca4)
                        table := f_4
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0da4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b44)
                        let var1 := sub(R, a_3)
                        let var2 := addmod(var0, var1, R)
                        let var3 := mulmod(var0, var2, R)
                        let var4 := mulmod(var0, var3, R)
                        let var5 := mulmod(f_12, var4, R)
                        let a_1 := calldataload(0x0b04)
                        let var6 := mulmod(var5, a_1, R)
                        let var7 := sub(R, var5)
                        let var8 := addmod(var0, var7, R)
                        let var9 := 0x0
                        let var10 := mulmod(var8, var9, R)
                        let var11 := addmod(var6, var10, R)
                        input_0 := var11
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1444), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1424), sub(R, calldataload(0x1404)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0cc4)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_11 := calldataload(0x0d84)
                        let var0 := 0x1
                        let a_2 := calldataload(0x0b24)
                        let var1 := mulmod(var0, a_2, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := mulmod(f_11, var2, R)
                        let a_0 := calldataload(0x0ae4)
                        let var4 := mulmod(var3, a_0, R)
                        let var5 := sub(R, var3)
                        let var6 := addmod(var0, var5, R)
                        let var7 := 0x1ffff8
                        let var8 := mulmod(var6, var7, R)
                        let var9 := addmod(var4, var8, R)
                        input_0 := var9
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x14a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1484), sub(R, calldataload(0x1464)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x14c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x14c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_5 := calldataload(0x0cc4)
                        table := f_5
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0da4)
                        let var0 := 0x1
                        let a_3 := calldataload(0x0b44)
                        let var1 := mulmod(var0, a_3, R)
                        let var2 := mulmod(var1, var0, R)
                        let var3 := mulmod(f_12, var2, R)
                        let a_1 := calldataload(0x0b04)
                        let var4 := mulmod(var3, a_1, R)
                        let var5 := sub(R, var3)
                        let var6 := addmod(var0, var5, R)
                        let var7 := 0x1ffff8
                        let var8 := mulmod(var6, var7, R)
                        let var9 := addmod(var4, var8, R)
                        input_0 := var9
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1504), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x14e4), sub(R, calldataload(0x14c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_6 := calldataload(0x0ce4)
                        table := f_6
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_13 := calldataload(0x0dc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_13, var0, R)
                        let a_0 := calldataload(0x0ae4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1564), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1544), sub(R, calldataload(0x1524)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_6 := calldataload(0x0ce4)
                        table := f_6
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0de4)
                        let var0 := 0x1
                        let var1 := mulmod(f_14, var0, R)
                        let a_1 := calldataload(0x0b04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x15c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x15a4), sub(R, calldataload(0x1584)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(coeff, addmod(point_0, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_2, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_3, sub(R, point_2), R), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ee4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x1044
                            let mptr_end := 0x0ee4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x0ec4
                            let mptr_end := 0x0c04
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x15c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1564), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1504), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x14a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1444), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x13e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1384), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1324), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x12c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1264), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1204), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x11a4), R), R)
                    for
                        {
                            let mptr := 0x0be4
                            let mptr_end := 0x0b64
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x0b44
                            let mptr_end := 0x0ac4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0c04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0b64), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1104), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x10c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x10e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x10a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1064), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1084), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1584), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x15a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1524), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1544), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x14c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x14e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1464), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1484), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1404), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1424), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x13a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x13c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1344), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1364), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x12e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1304), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1284), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x12a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1224), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1244), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x11c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x11e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1164), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1184), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1124), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1144), R), R)
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R), R)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x0964))
                    mstore(0x20, calldataload(0x0984))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1040
                            let mptr_end := 0x0800
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0564
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0164))
                    mstore(0xa0, calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x05e4))
                    mstore(0xa0, calldataload(0x0604))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x05a4), calldataload(0x05c4))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x0924))
                    mstore(0xa0, calldataload(0x0944))
                    for
                        {
                            let mptr := 0x08e4
                            let mptr_end := 0x05e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x15e4))
                    mstore(0xa0, calldataload(0x1604))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1624))
                    mstore(0xa0, calldataload(0x1644))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x1624))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x1644))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}