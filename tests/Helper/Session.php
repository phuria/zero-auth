<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\Helper;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\Middleware\SessionInterface;
use Phuria\ZeroAuth\Protocol\KeyPair;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class Session implements SessionInterface
{
    /**
     * @var BigInteger
     */
    private $sessionKey;

    /**
     * @var BigInteger
     */
    private $serverKeyPair;

    /**
     * @inheritdoc
     */
    public function getSessionKey()
    {
        return $this->sessionKey;
    }

    /**
     * @inheritdoc
     */
    public function setSessionKey(BigInteger $sessionKey)
    {
        $this->sessionKey = $sessionKey;
    }

    /**
     * @inheritdoc
     */
    public function getServerKeyPair()
    {
        return $this->serverKeyPair;
    }

    /**
     * @inheritdoc
     */
    public function setServerKeyPair(KeyPair $keyPair)
    {
        $this->serverKeyPair = $keyPair;
    }
}