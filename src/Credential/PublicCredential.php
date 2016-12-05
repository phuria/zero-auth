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

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class PublicCredential
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var BigInteger
     */
    private $salt;

    /**
     * @var BigInteger
     */
    private $verifier;

    /**
     * @param string     $username
     * @param BigInteger $salt
     * @param BigInteger $verifier
     */
    public function __construct($username, BigInteger $salt, BigInteger $verifier)
    {
        $this->username = $username;
        $this->salt = $salt;
        $this->verifier = $verifier;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return BigInteger
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @return BigInteger
     */
    public function getVerifier()
    {
        return $this->verifier;
    }
}