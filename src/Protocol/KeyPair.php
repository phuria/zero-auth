<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Protocol;

use phpseclib\Math\BigInteger;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class KeyPair
{
    /**
     * @var BigInteger
     */
    private $privateKey;

    /**
     * @var BigInteger
     */
    private $publicKey;

    /**
     * @param BigInteger $privateKey
     * @param BigInteger $publicKey
     */
    public function __construct(BigInteger $privateKey, BigInteger $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * @return BigInteger
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return BigInteger
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }
}