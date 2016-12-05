<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests;

use Phuria\ZeroAuth\Credential\CredentialTransformer;
use Phuria\ZeroAuth\Credential\PrivateCredential;
use Phuria\ZeroAuth\Tests\TestCase\ProtocolTestCase;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class ProtocolProcessTest extends \PHPUnit_Framework_TestCase
{
    use ProtocolTestCase;

    /**
     * @test
     * @small
     */
    public function itShouldGenerateSameKeys()
    {
        $helper = $this->createProtocolHelper();
        $privateCredential = new PrivateCredential('phuria', '12345');
        $credentialTransformer = new CredentialTransformer($helper);
        $publicCredential = $credentialTransformer->transform($privateCredential);

        // Step 1. Client generates client's KeyPair
        $clientKeyPair = $helper->generateClientKeyPair();

        // Step 2. Server generates server's KeyPair
        $serverKeyPair = $helper->generateServerKeyPair($publicCredential->getVerifier());

        // Step 3. Client and server computes scrambling
        $scrambling = $helper->computeScrambling($clientKeyPair->getPublicKey(), $serverKeyPair->getPublicKey());

        // Step 4. Client computes session key
        $credentialHash = $helper->computeCredentialsHash(
            $publicCredential->getSalt(),
            $publicCredential->getUsername(),
            $privateCredential->getPassword()
        );
        $clientSessionKey = $helper->computeClientSessionKey(
            $credentialHash,
            $serverKeyPair->getPublicKey(),
            $clientKeyPair->getPrivateKey(),
            $scrambling
        );

        // Step 5. Server computes session key
        $serverSessionKey = $helper->computeServerSessionKey(
            $clientKeyPair->getPublicKey(),
            $publicCredential->getVerifier(),
            $scrambling,
            $serverKeyPair->getPrivateKey()
        );

        static::assertHexSame($serverSessionKey->toHex(), $clientSessionKey->toHex());
    }
}