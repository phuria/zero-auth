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

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
interface UserProviderInterface
{
    /**
     * @return string
     */
    public function getUsername();

    /**
     * @return string
     */
    public function getSalt();

    /**
     * @return string
     */
    public function getVerifier();
}