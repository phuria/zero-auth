<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Credential;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\Protocol\ProtocolHelper;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class CredentialTransformer
{
    /**
     * @var ProtocolHelper
     */
    private $helper;

    /**
     * @param ProtocolHelper $helper
     */
    public function __construct(ProtocolHelper $helper)
    {
        $this->helper = $helper;
    }

    /**
     * @param PrivateCredential $credential
     * @param BigInteger        $salt
     *
     * @return PublicCredential
     */
    public function transform(PrivateCredential $credential, BigInteger $salt = null)
    {
        $salt = $salt ?: $this->helper->generateSalt();
        $credentialHash = $this->helper->computeCredentialsHash(
            $salt,
            $credential->getUsername(),
            $credential->getPassword()
        );
        $verifier = $this->helper->computeVerifier($credentialHash);

        return new PublicCredential($credential->getUsername(), $salt, $verifier);
    }
}