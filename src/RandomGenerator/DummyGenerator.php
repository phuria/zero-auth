<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\RandomGenerator;

use phpseclib\Math\BigInteger;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class DummyGenerator implements RandomGeneratorInterface
{
    const DUMMY_VALUE = '9d25f3b6ab8cfba5d2d68dc8d062988534a63e87';

    /**
     * @inheritdoc
     */
    public function generate($length = 64)
    {
        return new BigInteger(static::DUMMY_VALUE, 16);
    }
}