#!/bin/bash

set -e  # Exit on error
CIRCUIT_NAME="main"
PTAU_SIZE=16  # Adjust this based on circuit size

# Check if the secret key argument is provided
if [ -z "$1" ]; then
    echo "❌ No secret key provided. Please provide the secret key as the first argument."
    exit 1
fi

SECRET_INPUT=$1  # Get the secret key from the argument

echo "🚀 Starting Trusted Setup for Groth16..."

# Ensure snarkjs is installed
if ! command -v snarkjs &> /dev/null; then
    echo "❌ snarkjs not found! Install with: npm install -g snarkjs"
    exit 1
fi

# 1. Compile the circuit
echo "🔨 Compiling the circuit..."
circom ${CIRCUIT_NAME}.circom --r1cs --wasm --sym 

# 2. Start Powers of Tau ceremony
echo "🔑 Generating Powers of Tau (ptau)..."
snarkjs powersoftau new bn128 $PTAU_SIZE pot${PTAU_SIZE}_0000.ptau -v

# 3. Contribute randomness (User Secret Input)
echo "⚠️  Using provided secret key for contribution..."
echo $SECRET_INPUT | snarkjs powersoftau contribute pot${PTAU_SIZE}_0000.ptau pot${PTAU_SIZE}_0001.ptau --name="User Contribution" -v

# 4. Prepare phase 2
echo "🛠 Preparing Phase 2..."
snarkjs powersoftau prepare phase2 pot${PTAU_SIZE}_0001.ptau pot${PTAU_SIZE}_final.ptau -v

# 5. Generate zkey
echo "📜 Running Groth16 setup..."
snarkjs groth16 setup ${CIRCUIT_NAME}.r1cs pot${PTAU_SIZE}_final.ptau ${CIRCUIT_NAME}_0000.zkey -v

# 6. Contribute randomness for zkey
if [ -z "$2" ]; then
    echo "⚠️  No second secret key provided for zkey contribution. Please provide it as the second argument."
    exit 1
fi

SECRET_INPUT_2=$2  # Get the second secret key from the argument
echo "⚠️  Using second provided secret key for zkey contribution..."
echo $SECRET_INPUT_2 | snarkjs zkey contribute ${CIRCUIT_NAME}_0000.zkey ${CIRCUIT_NAME}_0001.zkey --name="User Contribution 2" -v

# 7. Export verification key
echo "📤 Exporting verification key..."
snarkjs zkey export verificationkey ${CIRCUIT_NAME}_0001.zkey verification_key.json

echo "✅ Trusted setup complete! Verification key stored as verification_key.json"
