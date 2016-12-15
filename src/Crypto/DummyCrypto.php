<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Crypto;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class DummyCrypto implements CryptoInterface
{
    /**
     * @inheritdoc
     */
    public function supports($cipher)
    {
        return true;
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data, $cipher, $sessionKey)
    {
        return $data;
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data, $cipher, $sessionKey)
    {
        return $data;
    }
}