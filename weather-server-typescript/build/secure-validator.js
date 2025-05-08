import { ethers } from "ethers";
// In-memory Nonce store implementation (production environments should use persistent storage)
export class InMemoryNonceStore {
    store = {}; // Key: signerAddress -> Key: session -> Value: nextExpectedNonce
    async getExpectedNonce(signerAddress, session) {
        console.log(`[NonceStore] Getting nonce: ${signerAddress} / ${session.substring(0, 8)}`);
        if (this.store[signerAddress] &&
            this.store[signerAddress][session] !== undefined) {
            console.log(`[NonceStore] Found: ${this.store[signerAddress][session]}`);
            return this.store[signerAddress][session];
        }
        console.log(`[NonceStore] Not found, returning 0`);
        return 0; // Default expected nonce for new sessions/signers
    }
    async incrementAndSetNonce(signerAddress, session, validatedNonce) {
        console.log(`[NonceStore] Incrementing nonce: ${signerAddress} / ${session.substring(0, 8)} from ${validatedNonce}`);
        if (!this.store[signerAddress]) {
            this.store[signerAddress] = {};
        }
        // The validated nonce is the received and expected nonce. The next expected nonce is validatedNonce + 1.
        this.store[signerAddress][session] = validatedNonce + 1;
        console.log(`[NonceStore] Next expected nonce set to: ${this.store[signerAddress][session]}`);
    }
}
/**
 * Validate DeProof in the request
 */
export async function validateDeProof(request, nonceStore, timeoutMs = 3000 // Default timeout is 3 seconds
) {
    const startTime = Date.now();
    console.log(`\n===== Starting DeProof validation =====`);
    try {
        // 1. Ensure the request contains DeProof
        const params = request.params;
        const deProof = params._deProof;
        if (!deProof) {
            console.error("Error: No _deProof object in the request");
            return {
                code: -32602,
                message: "Invalid request: Missing _deProof object",
            };
        }
        console.log(`Received DeProof: Signer=${deProof.signerAddress.substring(0, 8)}... Session=${deProof.session.substring(0, 8)}... Nonce=${deProof.nonce}`);
        // 2. Timestamp validation (allow 60 seconds tolerance)
        const TIME_TOLERANCE_SECONDS = 60;
        try {
            const requestTimestamp = new Date(deProof.timestamp).getTime();
            const currentTimestamp = Date.now();
            const diffSeconds = Math.abs(currentTimestamp - requestTimestamp) / 1000;
            console.log(`Timestamp validation: Request=${deProof.timestamp}, Current=${new Date().toISOString()}, Difference=${diffSeconds.toFixed(1)}seconds`);
            if (diffSeconds > TIME_TOLERANCE_SECONDS) {
                console.error(`Error: Timestamp out of tolerance range`);
                return {
                    code: -32001,
                    message: `Timestamp validation failed: Difference ${diffSeconds.toFixed(0)}seconds, allowed ${TIME_TOLERANCE_SECONDS}seconds`,
                };
            }
        }
        catch (error) {
            console.error(`Error: Invalid timestamp format`, error);
            return {
                code: -32002,
                message: `Timestamp validation failed: Invalid format`,
            };
        }
        // 3. Nonce validation
        try {
            const expectedNonce = await nonceStore.getExpectedNonce(deProof.signerAddress, deProof.session);
            if (deProof.nonce !== expectedNonce) {
                console.error(`Error: Nonce mismatch - Received=${deProof.nonce}, Expected=${expectedNonce}`);
                return {
                    code: -32003,
                    message: `Nonce validation failed: Received ${deProof.nonce}, Expected ${expectedNonce}`,
                };
            }
            console.log(`Nonce validation successful: ${deProof.nonce}`);
        }
        catch (error) {
            console.error(`Error: Nonce validation exception`, error);
            return {
                code: -32000,
                message: `Server error: Nonce store unavailable`,
            };
        }
        // 4. Reconstruct original data and calculate digest
        const actualParams = { ...params };
        delete actualParams._deProof;
        // Construct data to be validated
        const dataToVerify = {
            params: actualParams,
            nonce: deProof.nonce,
            session: deProof.session,
            timestamp: deProof.timestamp,
        };
        // Serialize data
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
        function canonicalStringify(value) {
            const sortedValue = sortObjectKeys(value);
            return JSON.stringify(sortedValue);
        }
        const serializedData = canonicalStringify(dataToVerify);
        console.log(`Serialized data: ${serializedData.substring(0, 100)}...`);
        // Calculate digest
        const calculatedDigest = ethers.utils.keccak256(Buffer.from(serializedData));
        const calculatedDigestWithoutPrefix = calculatedDigest.startsWith("0x")
            ? calculatedDigest.slice(2)
            : calculatedDigest;
        // Ensure digest format consistency
        const clientDigest = deProof.digest.startsWith("0x")
            ? deProof.digest.slice(2)
            : deProof.digest;
        console.log(`Digest validation: Client=${clientDigest.substring(0, 10)}..., Server=${calculatedDigestWithoutPrefix.substring(0, 10)}...`);
        if (calculatedDigestWithoutPrefix !== clientDigest) {
            console.error(`Error: Digest mismatch`);
            return {
                code: -32005,
                message: `Digest validation failed: Data may have been tampered with`,
            };
        }
        // 5. Validate signature
        try {
            // Client sends digest and signature without 0x prefix
            // Add prefix for ethers library to handle correctly
            const digestHex = clientDigest.startsWith("0x")
                ? clientDigest
                : "0x" + clientDigest;
            const signatureHex = deProof.signature.startsWith("0x")
                ? deProof.signature
                : "0x" + deProof.signature;
            const messageBytesThatWereSigned = Buffer.from(clientDigest, "hex");
            console.log(`Signature validation: Digest length=${messageBytesThatWereSigned.length}, Signature length=${signatureHex.length}`);
            // Validate signature
            const recoveredAddress = ethers.utils.verifyMessage(messageBytesThatWereSigned, signatureHex);
            console.log(`Signature validation: Recovered address=${recoveredAddress}, Declared signer=${deProof.signerAddress}`);
            if (recoveredAddress.toLowerCase() !== deProof.signerAddress.toLowerCase()) {
                console.error(`Error: Signature validation failed - Address mismatch`);
                return {
                    code: -32006,
                    message: `Signature validation failed: Address mismatch`,
                };
            }
        }
        catch (error) {
            console.error(`Error: Signature validation exception`, error);
            return {
                code: -32007,
                message: `Signature validation failed: ${error instanceof Error ? error.message : String(error)}`,
            };
        }
        // 6. Increment Nonce
        try {
            await nonceStore.incrementAndSetNonce(deProof.signerAddress, deProof.session, deProof.nonce);
            console.log(`Successfully incremented Nonce: ${deProof.nonce} -> ${deProof.nonce + 1}`);
        }
        catch (error) {
            console.error(`Critical error: Failed to update Nonce`, error);
            return {
                code: -32000,
                message: `Server error: Unable to update Nonce store`,
            };
        }
        const validationTime = Date.now() - startTime;
        console.log(`DeProof validation successful! Time taken ${validationTime}ms`);
        return null; // Validation passed, return null indicating no error
    }
    catch (error) {
        console.error(`DeProof validation exception:`, error);
        return {
            code: -32000,
            message: `DeProof validation failed: ${error instanceof Error ? error.message : String(error)}`,
        };
    }
}
