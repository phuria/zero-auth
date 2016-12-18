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

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
interface UserProviderInterface
{
    /**
     * @param string $username
     *
     * @return BigInteger
     */
    public function findVerifierByUsername($username);

    /**
     * @param string $username
     *
     * @return BigInteger
     */
    public function findSaltByUsername($username);
}