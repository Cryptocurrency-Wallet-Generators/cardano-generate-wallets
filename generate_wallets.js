const bip39 = require('bip39');
const CardanoWasm = require('@emurgo/cardano-serialization-lib-nodejs');
const fs = require('fs');

async function generateWallets(count) {
    const wallets = [];
    for (let i = 0; i < count; i++) {
        // Generate a 24-word mnemonic (strength 256 for 24 words)
        const mnemonic = bip39.generateMnemonic(256);
        
        // Create entropy from mnemonic
        const entropy = bip39.mnemonicToEntropy(mnemonic);
        
        // Create a private key from the entropy
        const rootKey = CardanoWasm.Bip32PrivateKey.from_bip39_entropy(
            Buffer.from(entropy, 'hex'),
            Buffer.from(''),  // password as buffer
        );
        
        // Derive account keys using path: m/1852'/1815'/0'
        // 1852' = purpose, 1815' = coin type for Cardano, 0' = account index
        const accountKey = rootKey
            .derive(1852 + 0x80000000) // purpose
            .derive(1815 + 0x80000000) // coin type
            .derive(0 + 0x80000000);   // account
            
        // Derive the stake key (2 in path represents staking key)
        const stakeKey = accountKey
            .derive(2) // 2 is for staking path
            .derive(0)
            .to_public();
            
        // Derive first address (external/payment key at index 0)
        const utxoKey = accountKey
            .derive(0) // 0 is external path
            .derive(0)
            .to_public();
            
        // Create address using payment and stake keys
        const baseAddr = CardanoWasm.BaseAddress.new(
            CardanoWasm.NetworkInfo.mainnet().network_id(),
            CardanoWasm.StakeCredential.from_keyhash(utxoKey.to_raw_key().hash()),
            CardanoWasm.StakeCredential.from_keyhash(stakeKey.to_raw_key().hash()),
        );
        
        // Get address as string
        const address = baseAddr.to_address().to_bech32();
        
        // Securely store the private key
        const privateKeyBytes = accountKey.to_raw_key().as_bytes();
        const privateKey = Buffer.from(privateKeyBytes).toString('hex');
        
        // Save wallet info
        wallets.push({
            address,
            privateKey,
            mnemonic
        });
        
        // Clean up to prevent memory leaks
        rootKey.free();
        accountKey.free();
        stakeKey.free();
        utxoKey.free();
        baseAddr.free();
    }

    return wallets;
}

async function main() {
    const walletCount = 50; // Number of wallets to generate
    const wallets = await generateWallets(walletCount);

    // Save wallets to a file
    const outputFileName = 'cardano_wallets.json';
    fs.writeFileSync(outputFileName, JSON.stringify(wallets, null, 2));

    console.log(`Generated ${walletCount} wallets and saved to ${outputFileName}`);
}

main().catch(console.error);
