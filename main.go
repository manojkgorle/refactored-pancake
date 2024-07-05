package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	gnark_verifier_types "github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type Plonky2xVerifierCircuit struct {
	// A digest of the plonky2x circuit that is being verified.
	VerifierDigest frontend.Variable `gnark:"verifierDigest,public"`

	// The input hash is the hash of all onchain inputs into the function.
	InputHash frontend.Variable `gnark:"inputHash,public"`

	// The output hash is the hash of all outputs from the function.
	OutputHash frontend.Variable `gnark:"outputHash,public"`

	// Private inputs to the circuit
	ProofWithPis variables.ProofWithPublicInputs
	VerifierData variables.VerifierOnlyCircuitData

	// Circuit configuration that is not part of the circuit itself.
	CommonCircuitData gnark_verifier_types.CommonCircuitData `gnark:"-"`
}

func (c *Plonky2xVerifierCircuit) Define(api frontend.API) error { return nil }

func GetInputHashOutputHash(proofWithPis gnark_verifier_types.ProofWithPublicInputsRaw) (*big.Int, *big.Int) {
	publicInputs := proofWithPis.PublicInputs
	if len(publicInputs) != 64 {
		panic("publicInputs must be 64 bytes")
	}
	publicInputsBytes := make([]byte, 64)
	for i, v := range publicInputs {
		publicInputsBytes[i] = byte(v & 0xFF)
	}
	inputHash := new(big.Int).SetBytes(publicInputsBytes[0:32])
	outputHash := new(big.Int).SetBytes(publicInputsBytes[32:64])
	if inputHash.BitLen() > 253 {
		panic("inputHash must be at most 253 bits")
	}
	if outputHash.BitLen() > 253 {
		panic("outputHash must be at most 253 bits")
	}
	return inputHash, outputHash
}

func main() {

	/// Method 1:

	// // b := common.Hex2Bytes("0x20b1cde5c2f8c1a0cee870bd75fadc9312dccbe590031f16bc4c918c182363cf1bbe26a52231ed0fefc41ff4fd2ffdfd199b71104ef65879d4b97bd2b24ab33d2605a7bab8987c9cab186910bcfc11107b25bd335423f8aa9c939e0f2233af0e24a7fce1132319828abc7838e860dbef2a0ecd30da39f0ac3c505b4dfaea5d2704806350d6f68630b3088898ad8a0ce99c38c6c5e82e068d93935e1a5bf657b805ac1b035ca22df3f5a698ad82478004cbbe54ee76ee1ae049ff1ac94921bd192b92ed9b79e220938d293c76a50be80b194b099f3e0f8c3ae3f388f5bdd391330f7e40c980cdfd4d3513a46187cc319625d01012d60321c0ae829955b6839e5915dfb7f54c02da566c8475e261dba48c32249e4ed8ba38b4a8b864e35e81177a15dd2467af161acd69ef92e8eded9c120a552e7c97b1258cdc3217176791702e0df6ec901d5051e5ebf8c51cff54fb10e4e0eedce44e5cc9bf7aa3ccebd243fe139ce4bdc28f2124f9c0192fa092e425802aa461938bf43759fc2de7c485fb802dc37f04b8b81e9907e31632b911132637a4be9aba3747a03568f1720cc2d6e52bcf74468a1e5fba119b2b7567d03f94ca36a52b4fb8f343875732c4710913a214a477be2653458084d9c054ff08df3b24e76dca8c746509ee42a684665f12ca2b93b606ca8a6d2d871f96c2ba628bdce8349b6a3667b7d01d9188b3cac5fd3006f42ed363a510cb18c5e66b2e310731744779fe1e128e742497ce7e2f5c0b4d2c7b0607b43fa416d9b136a0e951d5be9fa2e9387f150c1558d057200252045419558045d4c61171e241676fbf0a42cd5b32d6cdc2847596d117344a09f538732c2417ea4f24ec40124f0de3a715e22fadb5632be57b81bcf46f3a1eb85b2dd90e54ed15759dda276a17533e1ea03676701ae4ba4caa79012fe2423df721860e032c2e332a4ccce1c28ddf458d9fb580737257edd8729e3230af3fbdaf5257f9212c18c208871b2ebaceaa32b5b53170744792690090f2076d2f956a1aa0d9242af4661ccd3be5bb6ee04fa76c1a882c2b7582dc0dad8a61fa7623c3b626474a2bbbea7fd43a580d05457cba27008f9f584b06e0d14803ace0d2f94bfd8324681c71a9945033db5fbef305e2246023c757f4adff151cb4c04b1bb36d87885d741b83ffd804ad0a594dee8bea63d5123bd3f2aa52a6ff2c4f5ea0a31b6a9792d302b63dc52d00aee6102f2dbd6602b4d3683f0846a9372b025b9e66d02b17eac00b4a0e2beebe2065267f933b443aa2ca6240bfd75d115ab0b43a8710e384403c")
	// // proof3 := plonk_bn254.UnmarshalSolidity(b, 1)
	// // fmt.Println(proof3)
	data, _ := os.ReadFile("/home/ubuntu/blobstreamx/proofs/proof_raw_7590dff7-8e33-49c9-87bb-f43a5100c829.json")
	proof := plonk.NewProof(ecc.BN254)
	fmt.Println(common.Bytes2Hex(data))
	_, err := proof.ReadFrom(bytes.NewBuffer(data))
	if err != nil {
		fmt.Println(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	data, _ = os.ReadFile("/home/ubuntu/blobstreamx/artifacts/verifier-build/vk.bin")
	vk.ReadFrom(bytes.NewBuffer(data))
	// common.Bytes2Hex(data)
	// hexadecimal encoded vk bytes
	// "000000000200000030644e5aaf0a66b91f8030da595e7d1c6787b9b45fc54c546729acf1ff0536092a734ebb326341efa19b0361d9130cd47b26b7488dc6d26eeccd4f3eb878331a00000000000000030000000000000000000000000000000000000000000000000000000000000005ddfd2fca10f4194aadf247110274b824a53b3c6f3a40ac196c4b53d87232d8bcdf3309b87358d63f00654135d40e456401c865c8385f77306c6c19d782bbd394df4e7f547afa6028f973d6dd170d1bc12b3d3e20fdce28222ec037af56a358d4de0b04148e3a9f7eb51212e8526d09dd56dc3edb565ccc45416c9fba25fc1c2feff78223f37bf8b778362339c511b9e53e716b1b1dcca9e509a3a2a3c93cf97bcd833c720407c3e48a8a7f108f9dd312e238391ac55e90f96832dc8062ac33a3c678bd6d6921cee9658141afbc8cc997dadc274997625edbc36a3a29eacd1539e9c5c92a49a34529a5ee0a72b5a1196ac1815979e6a145aae01ce62f11b151d600000001a71c15245004727332eaff229c43cf099c25a86d82ff312a1c84fa5606544cd9dfa4be93b5e7f7e674d5059b63554fab99638b304ed8310e9fa44c281ac9b03b998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6eda2f1acbb03c4508760c2430af35865e7cdf9f3eb1224504fdcc3708ddb954a482a344fad01c2ed0ed73142ae1752429eaea515c6f3f6b941103cc21c2308e1cb00000001000000000093fa0d"
	// wit, err := witness.New(ecc.BN254.ScalarField())
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// // data, _ = os.ReadFile("/home/ubuntu/blobstreamx/proofs/public_witness_ae8892d3-667c-49ad-ad10-637e053adc77.json")
	// data, _ = os.ReadFile("/home/ubuntu/blobstreamx/proofs/public_witness.bin")
	// pubWit, err := wit.Public()
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// pubWit.ReadFrom(bytes.NewBuffer(data))

	// // fmt.Println(proof)
	// // fmt.Println(plonk_bn254.Unmarshalsolidity(proof.(*plonk_bn254.Proof).MarshalSolidity(), 1))
	// fmt.Println(plonk.Verify(proof, vk, pubWit))

	/// Method 2: hash inputs and outputs.
	input, _ := hexutil.Decode("0x00000000001356004531e3d45ac1540eb279659b782a0c495f2fc2b6bb2af5a8648f9aa7dafca6650000000000135762")
	output, _ := hexutil.Decode("0xfa9c83f070c75a99fd2dc5cebbf66f432cb42e8ae3945c484a52a6993ac17f020a736aa7f7c93752e6d0994393e98aa290d15f92775805eb7ab75bba93bbfb57")
	// digest, _ := hexutil.Decode("0x16df4a97d228dbf5c20398fa31357d96724dcd1df399d9919b2902f6a42850f1")
	circuitDigestBigInt, _ := new(big.Int).SetString("10310189448205051960894735306968713236725543474929808083983647516402594023487", 10)
	circuitDigestVar := frontend.Variable(circuitDigestBigInt)
	digest := poseidon.BN254HashOut(circuitDigestVar)
	// l := len(input)
	//@todo we suspect this check of l-8 is only for next header. -> suspection is correct
	// inputHash := sha256.Sum256(input[:l-8])
	inputHash := sha256.Sum256(input)
	outputHash := sha256.Sum256(output)

	fmt.Println("input bytes", input)
	fmt.Println("output bytes", output)

	fmt.Println("input hash", common.Bytes2Hex(inputHash[:]))
	fmt.Println("output hash", common.Bytes2Hex(outputHash[:]))
	/// ----  this data is for next header ----
	// 	for next header, no need of target block
	// 	 Input Bytes: 0x00000000001354d46138cf9addf5fb9d6c4a5409614ef477f5d803e68bfaa4d5eb82f01480e17f3a000000000013560e
	//  Output Bytes: 0x3f0d6bf4a31b826fc41412d1d9de6beeaea88d4a41ff627b554cc0cfe4e6b4e2c774ddb15226098bf286065460da8ccd6d2eabcb56ea6597f9971d7875e179ea
	//  output_bytes: [63, 13, 107, 244, 163, 27, 130, 111, 196, 20, 18, 209, 217, 222, 107, 238, 174, 168, 141, 74, 65, 255, 98, 123, 85, 76, 192, 207, 228, 230, 180, 226, 199, 116, 221, 177, 82, 38, 9, 139, 242, 134, 6, 84, 96, 218, 140, 205, 109, 46, 171, 203, 86, 234, 101, 151, 249, 151, 29, 120, 117, 225, 121, 234]
	//   input_bytes: [0, 0, 0, 0, 0, 19, 84, 212, 97, 56, 207, 154, 221, 245, 251, 157, 108, 74, 84, 9, 97, 78, 244, 119, 245, 216, 3, 230, 139, 250, 164, 213, 235, 130, 240, 20, 128, 225, 127, 58]
	//  output_hash_truncated: 0x136bff89625086494eaa0d66d83974d38b052a48d97e3ced8083233ef0b6f398
	//  input_hash_truncated: 0x0e415a6afe8a4e3393bf2d3e0630a68ed34d5dfbfb113db3b1927dd6bdd8aa43
	//  output_hash: 0x336bff89625086494eaa0d66d83974d38b052a48d97e3ced8083233ef0b6f398
	//  input_hash: 0xee415a6afe8a4e3393bf2d3e0630a68ed34d5dfbfb113db3b1927dd6bdd8aa43
	//  input_hash_truncated as vars: [14, 65, 90, 106, 254, 138, 78, 51, 147, 191, 45, 62, 6, 48, 166, 142, 211, 77, 93, 251, 251, 17, 61, 179, 177, 146, 125, 214, 189, 216, 170, 67]
	//  output_hash_truncated as vars: [19, 107, 255, 137, 98, 80, 134, 73, 78, 170, 13, 102, 216, 57, 116, 211, 139, 5, 42, 72, 217, 126, 60, 237, 128, 131, 35, 62, 240, 182, 243, 152]

	// -- this data is for header range ---
	// target block is needed for header range
	// 	 Input Bytes: 0x00000000001356004531e3d45ac1540eb279659b782a0c495f2fc2b6bb2af5a8648f9aa7dafca6650000000000135762
	//  Output Bytes: 0xfa9c83f070c75a99fd2dc5cebbf66f432cb42e8ae3945c484a52a6993ac17f020a736aa7f7c93752e6d0994393e98aa290d15f92775805eb7ab75bba93bbfb57
	//  output_bytes: [250, 156, 131, 240, 112, 199, 90, 153, 253, 45, 197, 206, 187, 246, 111, 67, 44, 180, 46, 138, 227, 148, 92, 72, 74, 82, 166, 153, 58, 193, 127, 2, 10, 115, 106, 167, 247, 201, 55, 82, 230, 208, 153, 67, 147, 233, 138, 162, 144, 209, 95, 146, 119, 88, 5, 235, 122, 183, 91, 186, 147, 187, 251, 87]
	//  input_bytes: [0, 0, 0, 0, 0, 19, 86, 0, 69, 49, 227, 212, 90, 193, 84, 14, 178, 121, 101, 155, 120, 42, 12, 73, 95, 47, 194, 182, 187, 42, 245, 168, 100, 143, 154, 167, 218, 252, 166, 101, 0, 0, 0, 0, 0, 19, 87, 98]
	//  output_hash_truncated: 0x1e80cf1ff73ccdfe5c4e86601a39577e3c00949b0947b58fa1c4d0787719ef4a
	//  output_hash: 0x3e80cf1ff73ccdfe5c4e86601a39577e3c00949b0947b58fa1c4d0787719ef4a
	//  input_hash_truncated: 0x1dab877d891a0f102898d5965f756ef6befe257f3ee0214118e997785964a8a4
	//  input_hash: 0xbdab877d891a0f102898d5965f756ef6befe257f3ee0214118e997785964a8a4
	//  output_hash_truncated as vars: [30, 128, 207, 31, 247, 60, 205, 254, 92, 78, 134, 96, 26, 57, 87, 126, 60, 0, 148, 155, 9, 71, 181, 143, 161, 196, 208, 120, 119, 25, 239, 74]
	//  input_hash_truncated as vars: [29, 171, 135, 125, 137, 26, 15, 16, 40, 152, 213, 150, 95, 117, 110, 246, 190, 254, 37, 127, 62, 224, 33, 65, 24, 233, 151, 120, 89, 100, 168, 164]
	//----------------------------------------
	inputHashB := new(big.Int).SetBytes(inputHash[:])
	outputHashB := new(big.Int).SetBytes(outputHash[:])
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 253), big.NewInt(1))
	inputHashM := new(big.Int).And(inputHashB, mask)
	outputHashM := new(big.Int).And(outputHashB, mask)

	//we need to mask the values either as in soldity verifier or wrapper
	if inputHashM.BitLen() > 253 {
		panic("inputHash must be at most 253 bits")
	}
	if outputHashM.BitLen() > 253 {
		panic("outputHash must be at most 253 bits")
	}
	fmt.Println("input hash trunc", inputHashM.Bytes())
	fmt.Println("output hash trunc", outputHashM.Bytes())
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(
		gnark_verifier_types.ReadVerifierOnlyCircuitData("/home/ubuntu/blobstreamx/proofs/verifier_only_circuit_data.json"),
	)
	proofWithPis := gnark_verifier_types.ReadProofWithPublicInputs("/home/ubuntu/blobstreamx/proofs/proof_with_public_inputs.json")
	proofWithPisVariable := variables.DeserializeProofWithPublicInputs(proofWithPis)

	witI := Plonky2xVerifierCircuit{
		InputHash:      frontend.Variable(inputHashM),
		OutputHash:     frontend.Variable(outputHashM),
		VerifierDigest: digest,
		VerifierData:   verifierOnlyCircuitData,
		ProofWithPis:   proofWithPisVariable,
	}

	wit, _ := frontend.NewWitness(&witI, ecc.BN254.ScalarField())
	pubWitI, _ := wit.Public()
	// issue is with the proof unmarshalling.
	fmt.Println(plonk.Verify(proof, vk, pubWitI))
}
