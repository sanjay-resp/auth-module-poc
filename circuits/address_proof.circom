pragma circom 2.0.0;

include "/home/sanjay/circomlib/circuits/eddsamimc.circom";
include "/home/sanjay/circomlib/circuits/poseidon.circom";
include "/home/sanjay/circomlib/circuits/escalarmul.circom";


template JWTValidation() {
    signal input google_pubkey_x;
    signal input google_pubkey_y;
    signal input nonce;
    signal input address;
    signal input epk_x;
    signal input epk_y;
    signal input tpub_x;
    signal input tpub_y;
    signal input sig_R8x;
    signal input sig_R8y;
    signal input sig_S;

    signal input jwt_message;
    signal input jwt_sig_R8x;
    signal input jwt_sig_R8y;
    signal input jwt_sig_S;
    signal input blinding_factor;
    signal input sid;
    signal input aud;
    signal input spice;
    // signal input tpsk;

    // Constants
    //  var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553, 
    //  16950150798460657717958625567821834550301663161624707787222815936182638968203];

    // 1. JWT Signature Verification
    component jwtVerifier = EdDSAMiMCVerifier();
    jwtVerifier.enabled <== 1;
    jwtVerifier.Ax <== google_pubkey_x;
    jwtVerifier.Ay <== google_pubkey_y;
    jwtVerifier.R8x <== jwt_sig_R8x;
    jwtVerifier.R8y <== jwt_sig_R8y;
    jwtVerifier.S <== jwt_sig_S;
    jwtVerifier.M <== jwt_message;

    // 2. Nonce Verification
    component nonceHasher = Poseidon(3);
    nonceHasher.inputs[0] <== epk_x;
    nonceHasher.inputs[1] <== epk_y;
    nonceHasher.inputs[2] <== blinding_factor;
    nonceHasher.out === nonce;

    // 3. Address Generation
    component addrHasher = Poseidon(3);
    addrHasher.inputs[0] <== sid;
    addrHasher.inputs[1] <== aud;
    addrHasher.inputs[2] <== spice;
    addrHasher.out === address;

    // 4.1 Public Key Generation
    // component tpubGenerator = EscalarMul(256, base);
    // signal tpub_x_computed;
    // signal tpub_y_computed;

    // tpubGenerator.in <== tpsk;   // Use `in` instead of `e` (depends on EscalarMul implementation)
    // tpub_x_computed <== tpubGenerator.out[0];
    // tpub_y_computed <== tpubGenerator.out[1];

    // tpub_x === tpub_x_computed;
    // tpub_y === tpub_y_computed;


    // 4.2 Message Hashing
    component msgHasher = Poseidon(5);
    msgHasher.inputs[0] <== addrHasher.out;
    msgHasher.inputs[1] <== epk_x;
    msgHasher.inputs[2] <== epk_y;
    msgHasher.inputs[3] <== google_pubkey_x;
    msgHasher.inputs[4] <== google_pubkey_y;

    // 4.3 Signature Verification
    component sigVerifier = EdDSAMiMCVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== tpub_x;
    sigVerifier.Ay <== tpub_y;
    sigVerifier.R8x <== sig_R8x;
    sigVerifier.R8y <== sig_R8y;
    sigVerifier.S <== sig_S;
    sigVerifier.M <== msgHasher.out;
}

component main {public [google_pubkey_x, google_pubkey_y, nonce, address, epk_x, epk_y, tpub_x, tpub_y, sig_R8x, sig_R8y, sig_S]} = JWTValidation();