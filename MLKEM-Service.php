<?php

namespace App\Services\Encryption;

use App\Exceptions\KemException;
use FFI;

class KemService
{
    private string $algorithm;
    private FFI $oqs;

    /**
     * Initializes the service and loads liboqs bindings via FFI.
     */
    public function __construct(string $algorithm = 'ML-KEM-1024')
    {
        $this->algorithm = $algorithm;

        // Fetch paths from config with fallback defaults
        $headerPath = config('liboqs.header_path');
        $libraryPath = config('liboqs.library_path');

        // Validate that the header file exists
        if (!file_exists($headerPath)) {
            throw new \RuntimeException("OQS header file not found at: {$headerPath}");
        }

        // Validate that the shared library exists
        if (!file_exists($libraryPath)) {
            throw new \RuntimeException("liboqs shared library (.so) not found at: {$libraryPath}");
        }

        // Load the liboqs C interface using FFI
        $this->oqs = FFI::cdef(
            file_get_contents($headerPath),
            $libraryPath
        );
    }

    /**
     * Generate a public/secret key pair using the specified post-quantum KEM algorithm.
     * @return array
     * @throws KemException
     */
    public function generateKeyPair(): array
    {
        // Initialize the KEM algorithm
        $kem = $this->createKemInstance();

        try {
            // Get public and secret key lengths from the KEM struct
            $publicKeyLength = $kem->length_public_key;
            $secretKeyLength = $kem->length_secret_key;

            // Allocate buffers for the public and secret keys
            $publicKeyBuffer = $this->allocateBuffer($publicKeyLength);
            $secretKeyBuffer = $this->allocateBuffer($secretKeyLength);

            // Generate keypair using the selected KEM algorithm
            if ($this->oqs->OQS_KEM_keypair($kem, $publicKeyBuffer, $secretKeyBuffer) !== 0) {
                throw new KemException('Keypair generation failed.');
            }

            // Return hex-encoded public and secret keys
            return [
                'public_key' => bin2hex(FFI::string($publicKeyBuffer, $publicKeyLength)),
                'secret_key' => bin2hex(FFI::string($secretKeyBuffer, $secretKeyLength)),
            ];

        } finally {
            // Clean up KEM resources
            $this->oqs->OQS_KEM_free($kem);
        }
    }

    /**
     * Encapsulates a shared secret for the given public key using a post-quantum KEM algorithm.
     * @param  string  $publicKeyHex
     * @return array
     * @throws KemException
     */
    public function encapsulate(string $publicKeyHex): array
    {
        // Initialize the KEM context
        $kem = $this->createKemInstance();

        try {
            // Get lengths from the KEM struct
            $publicKeyLength = $kem->length_public_key;
            $ciphertextLength = $kem->length_ciphertext;
            $sharedSecretLength = $kem->length_shared_secret;

            // Ensure the hex string has an even number of characters (2 characters per byte)
            if (strlen($publicKeyHex) % 2 !== 0) {
                throw new KemException('Invalid hex string: length must be even.');
            }

            // Convert hex string to binary and validate length
            $publicKeyBinary = $this->decodeHex($publicKeyHex, 'public key');

            if ($publicKeyBinary === false || strlen($publicKeyBinary) !== $publicKeyLength) {
                throw new KemException('Invalid public key length or format');
            }

            // Allocate memory buffers for input and output
            $publicKeyBuffer = $this->allocateBuffer($publicKeyLength, $publicKeyBinary);
            $ciphertextBuffer = $this->allocateBuffer($ciphertextLength);
            $sharedSecretBuffer = $this->allocateBuffer($sharedSecretLength);

            // Perform encapsulation with the provided public key
            if ($this->oqs->OQS_KEM_encaps($kem, $ciphertextBuffer, $sharedSecretBuffer, $publicKeyBuffer) !== 0) {
                throw new KemException('Encapsulation failed.');
            }

            // Return results as hex-encoded strings
            return [
                'ciphertext' => bin2hex(FFI::string($ciphertextBuffer, $ciphertextLength)),
                'shared_secret' => bin2hex(FFI::string($sharedSecretBuffer, $sharedSecretLength)),
            ];

        } finally {
            // Clean up KEM instance
            $this->oqs->OQS_KEM_free($kem);
        }
    }

    /**
     * Decapsulates a shared secret from the given ciphertext and secret key using a KEM algorithm.
     * @param  string  $ciphertextHex
     * @param  string  $secretKeyHex
     * @return string
     * @throws KemException
     */
    public function decapsulate(string $ciphertextHex, string $secretKeyHex): string
    {
        // Initialize the KEM context
        $kem = $this->createKemInstance();

        try {
            // Get lengths from the KEM struct
            $ciphertextLength = $kem->length_ciphertext;
            $secretKeyLength = $kem->length_secret_key;
            $sharedSecretLength = $kem->length_shared_secret;

            // Convert hex-encoded inputs to binary
            $ciphertextBinary = $this->decodeHex($ciphertextHex, 'ciphertext');
            $secretKeyBinary = $this->decodeHex($secretKeyHex, 'secret key');

            if (
                $ciphertextBinary === false || $secretKeyBinary === false ||
                strlen($ciphertextBinary) !== $ciphertextLength ||
                strlen($secretKeyBinary) !== $secretKeyLength
            ) {
                throw new KemException('Invalid ciphertext or secret key length or format.');
            }

            // Prepare FFI memory buffers for input and output
            $ciphertextBuffer = $this->allocateBuffer($ciphertextLength, $ciphertextBinary);
            $secretKeyBuffer = $this->allocateBuffer($secretKeyLength, $secretKeyBinary);
            $sharedSecretBuffer = $this->allocateBuffer($sharedSecretLength);

            // Perform decapsulation using the secret key and ciphertext
            if ($this->oqs->OQS_KEM_decaps($kem, $sharedSecretBuffer, $ciphertextBuffer, $secretKeyBuffer) !== 0) {
                throw new KemException('Decapsulation failed.');
            }

            // Return the shared secret as a hex-encoded string
            return bin2hex(FFI::string($sharedSecretBuffer, $sharedSecretLength));

        } finally {
            // Clean up KEM instance
            $this->oqs->OQS_KEM_free($kem);
        }
    }

    /**
     * Create a new KEM instance.
     * @return FFI\CData
     * @throws KemException
     */
    private function createKemInstance(): FFI\CData
    {
        $kem = $this->oqs->OQS_KEM_new($this->algorithm);
        if ($kem === null) {
            throw new KemException("Failed to initialize KEM algorithm: $this->algorithm");
        }

        return $kem;
    }

    /**
     *  Allocates an uint8_t buffer of the given length.
     *  Optionally copies binary data into the buffer.
     * @param  int  $length
     * @param  string|null  $data
     * @return FFI\CData
     */
    private function allocateBuffer(int $length, ?string $data = null): FFI\CData
    {
        // Allocate a C buffer of type uint8_t[length]
        $buf = FFI::new("uint8_t[{$length}]");

        if ($data !== null) {
            // Copy PHP binary string into C buffer
            // Required because direct assignment to a C array is not allowed
            FFI::memcpy($buf, $data, $length);
        }

        return $buf;
    }

    /**
     * Safely converts a hex-encoded string to binary after validating it.
     *
     * @param string $hex
     * @param string $label
     * @return string
     * @throws KemException
     */
    private function decodeHex(string $hex, string $label): string
    {
        $hex = strtolower(trim($hex));

        if (!ctype_xdigit($hex)) {
            throw new KemException("Invalid {$label}: contains non-hexadecimal characters.");
        }

        if (strlen($hex) % 2 !== 0) {
            throw new KemException("Invalid {$label}: hex string must have even length.");
        }

        return hex2bin($hex);
    }
}
