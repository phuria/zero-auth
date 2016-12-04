<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\UserProvider;

use Phuria\ZeroAuth\Protocol\Calculator;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class UserProvider implements UserProviderInterface
{
    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $salt;

    /**
     * @var string
     */
    private $verifier;

    public function createFromCredentials(Calculator $calculator, $username, $password)
    {
        $salt = $calculator->generateSalt();
    }

    /**
     * @param string $username
     * @param string $salt
     * @param string $verifier
     */
    public function __construct($username, $salt, $verifier)
    {
        $this->username = $username;
        $this->salt = $salt;
        $this->verifier = $verifier;
    }

    /**
     * @inheritdoc
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @inheritdoc
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @inheritdoc
     */
    public function getVerifier()
    {
        return $this->verifier;
    }
}