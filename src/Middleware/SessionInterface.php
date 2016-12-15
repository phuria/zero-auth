<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Middleware;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\Protocol\KeyPair;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
interface SessionInterface
{
    /**
     * @return BigInteger
     */
    public function getSessionKey();

    /**
     * @param BigInteger $sessionKey
     */
    public function setSessionKey(BigInteger $sessionKey);

    /**
     * @return KeyPair
     */
    public function getServerKeyPair();

    /**
     * @param KeyPair $keyPair
     */
    public function setServerKeyPair(KeyPair $keyPair);
}