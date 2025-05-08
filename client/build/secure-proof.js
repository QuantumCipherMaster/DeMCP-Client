import { randomUUID } from "crypto";
import { keccak256 } from "ethers";
// Nonce storage - stored in client session
const nonceStore = {};
/**
 * Get and increment the nonce for the specified signer address and session
 */
export function getAndIncNonce(signerAddress, session) {
    if (!nonceStore[signerAddress]) {
        nonceStore[signerAddress] = {};
    }
    if (nonceStore[signerAddress][session] === undefined) {
        nonceStore[signerAddress][session] = 0;
    }
    const currentNonce = nonceStore[signerAddress][session];
    nonceStore[signerAddress][session]++;
    return currentNonce;
}
/**
 * Serialize request content for signing
 * Ensure all relevant fields are included and sorted in a stable order
 */
function sortObjectKeys(obj) {
    if (typeof obj !== "object" || obj === null) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(sortObjectKeys);
    }
    return Object.keys(obj)
        .sort()
        .reduce((acc, key) => {
        acc[key] = sortObjectKeys(obj[key]);
        return acc;
    }, {});
}
/**
 * Generate a canonical string representation of parameters
 */
export function canonicalStringify(value) {
    const sortedValue = sortObjectKeys(value);
    return JSON.stringify(sortedValue);
}
/**
 * Generate a DeProof object for request parameters
 */
export async function generateDeProof(params, wallet, currentSession) {
    // Use current session or create a new one
    const session = currentSession ?? randomUUID();
    const timestamp = new Date().toISOString();
    const nonce = getAndIncNonce(wallet.address, session);
    // Create data for signing
    const dataToSign = {
        params: params,
        nonce,
        session,
        timestamp,
    };
    // 1. Serialize request data
    const serializedData = canonicalStringify(dataToSign);
    console.log("Serialized data:", serializedData);
    // 2. Calculate the digest
    const digest = keccak256(Buffer.from(serializedData));
    // Remove the 0x prefix to reduce data size
    const digestWithoutPrefix = digest.startsWith("0x")
        ? digest.slice(2)
        : digest;
    console.log("Calculated digest:", digest);
    // 3. Use the wallet private key to sign the digest
    const messageBytes = Buffer.from(digestWithoutPrefix, "hex");
    const signature = await wallet.signMessage(messageBytes);
    // Remove the 0x prefix to reduce data size
    const signatureWithoutPrefix = signature.startsWith("0x")
        ? signature.slice(2)
        : signature;
    console.log("Generated signature:", signature.substring(0, 20) + "...");
    // 4. Construct and return the DeProof object
    return {
        signerAddress: wallet.address,
        nonce,
        session,
        timestamp,
        digest: digestWithoutPrefix,
        signature: signatureWithoutPrefix,
    };
}
