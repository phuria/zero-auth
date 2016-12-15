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

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
interface SessionInterface
{
    /**
     * @return string
     */
    public function getSessionKey();

    /**
     * @param string $sessionKey
     *
     * @return mixed
     */
    public function setSessionKey($sessionKey);
}