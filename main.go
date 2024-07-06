package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
)

type SP1Circuit struct {
	VkeyHash             frontend.Variable `gnark:",public"`
	CommitedValuesDigest frontend.Variable `gnark:",public"`
	Vars                 []frontend.Variable
	Felts                []babybearVariable
	Exts                 []babybearExtensionVariable
}

func (*SP1Circuit) Define(frontend.API) error {
	return nil
}

type babybearVariable struct {
	Value  frontend.Variable
	NbBits uint
}

type babybearExtensionVariable struct {
	Value [4]babybearVariable
}

func main() {
	proofData := "244e7b9370d3380deeff6340beadf03a8f584235d135e8e91095ac512fbd623b0951e0bdc6960f9115632aeb2715ac4bd39c16af03668159657270b8a0e01fe01c80f3578780b4fabeb831f51e9a2fc13dd966396d24b4bf5ed776df252d254b2b049e67c7f48eba905f332c5c6864ad5963ab20fc7ce27be4665d9c508b73c92274409ea6382d1b2e7db12f5c6274e71a085105d0feb0b1e7b76e5b0ecd6751054c8573b81e5381886b1a59d84626501942b2fd27c0380cc1a072fa0e89013b00dcdb5030d760ad2813e3cff52b5b63289f61c793f067bdfeef27df560e50df286d1d3c6d4966d1e4e1ba6cd811b6056ea80dbd650624f338addbce6f5c04ac1166db59d30b59e37812d63e219533f9a42ead2e5c633723987f1fd8241dd12826ecb0cc7ae72af7e90cceb5b2d01f8cafb16a2c603272f363e088a94ab5b74c05cd243c82d17e6a9aeceb7c5ff41600d2adeb83105e576d731eee02da58e95116dfa8f982f0c94c448028425a7e896082c68c6b2174856306192acadf1557fa0bf78b5b4ef07b5176d3ec45ee40304ea754a1b32951b08454c6b5e4d07e196703543dae9e5f5b2e9a08451bd01adf7cf3a6c35784c53f56fb0bb8ac368afc0a1e1b3a2bcf7aeeb32c4021cc7543c0bd2b4ad181c90b0442172db7d24dbe6be712542de410c22c1c2bf2593caeb7517f2c8986b8ea7463bf87848970b9dff7b400000007267459b6e97a3ee95dbac22ee24444bc22a433e52c20f7847bd253261a43965c1afda52230d7885632811c9608817c694efc563f07828394306a13795fb9559c1f7e71266f3ebe99dbec2f31118eab3c5959cdec5a9af80ae26c27896a2eee3412933ef1ca07e738604ad2520b1e47a85f5be64974dffb74ea27ff8e1ea85e2c12f39a1b85d95e7f0210ee4bed6c6bab5f9b730496b067f39336c6aad9097b3e1e7f976c0859eec6fb8e94220cae0ce8d01774057a6f1316c0c312453d6ec2bd255fe341459509a3867ee1bc6ecbb58de487141ed90e63b42a2164e8825092e92ffc75199966d6774a499c65f7e654d10e7a1dea2a056086e8d2e1e28cface1c2db9608c69874f762c7f3f1fd45dd4f719b77a3f56b55eab22e334ca9384911b115659d31d6a744e994ed42141a239e9b740137a4fd5dcd27d0d04b5fd0cf305000000012f6315f6219fc990b0accef92e45f47e7e26654a10cc5c71267384bd089309e8299de2e8cd06931596485f24160415f0ccf1da3e7430722629122102dfc21710"
	proofDatab, err := hex.DecodeString(proofData)
	if err != nil {
		panic(err)
	}
	proof := plonk.NewProof(ecc.BN254)
	if _, err = proof.ReadFrom(bytes.NewReader(proofDatab)); err != nil {
		fmt.Println(err)
	}

	// vkeyHashStr := string([]byte{128, 28, 102, 172, 17, 189, 109, 146, 218, 55, 133, 53, 114, 20, 104, 101, 110, 82, 114, 166, 209, 146, 58, 101, 238, 59, 153, 118, 17, 214, 156, 197})
	// fmt.Println("vkey hash", vkeyHashStr)
	vkeyHashStr := "414456900754233403821469318749333346230962952863679230760144647782402486705"
	vkFile, err := os.Open("/home/ubuntu/.sp1/circuits/plonk_bn254/v1.0.8-testnet/vk.bin")
	if err != nil {
		panic(err)
	}
	vk := plonk.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(vkFile)
	publicValues := []byte{24, 139, 112, 139, 238, 24, 15, 67, 227, 162, 82, 71, 23, 84, 253, 53, 40, 58, 107, 9, 166, 253, 2, 245, 185, 19, 12, 193, 86, 4, 248, 11, 120, 217, 248, 212, 215, 175, 104, 226, 124, 224, 103, 116, 116, 128, 32, 177, 63, 77, 246, 212, 243, 109, 253, 151, 94, 70, 97, 79, 141, 148, 26, 173, 193, 178, 27, 106, 213, 42, 34, 8, 11, 251, 159, 166, 241, 188, 123, 221, 83, 199, 60, 155, 30, 65, 254, 210, 193, 210, 177, 234, 235, 220, 251, 142, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 154, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 154, 198, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	publicValuesHash := sha256.Sum256(publicValues)
	fmt.Println("public values hash", common.Bytes2Hex(publicValuesHash[:]))
	publicValuesB := new(big.Int).SetBytes(publicValuesHash[:])

	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 253), big.NewInt(1))
	publicValuesM := new(big.Int).And(publicValuesB, mask)

	//we need to mask the values either as in soldity verifier or wrapper
	if publicValuesM.BitLen() > 253 {
		panic("pub val hash must be at most 253 bits")
	}
	fmt.Println("public values hash masked", publicValuesM)
	// pubValStr := "2207589073904767922414076570328352545669146104703924897671640499787200195515"
	sp1Circuit := SP1Circuit{
		Vars:                 []frontend.Variable{},
		Felts:                []babybearVariable{},
		Exts:                 []babybearExtensionVariable{},
		VkeyHash:             vkeyHashStr,
		CommitedValuesDigest: publicValuesM,
	}
	// fmt.Println("vkey hash", sp1Circuit.VkeyHash)
	witness, err := frontend.NewWitness(&sp1Circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Println(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println(err)
	}
	// issue is with the proof unmarshalling.
	fmt.Println(plonk.Verify(proof, vk, publicWitness))
}
