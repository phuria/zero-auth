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
class RandomBytesGenerator implements RandomGeneratorInterface
{
    /**
     * @inheritdoc
     */
    public function generate($length = 64)
    {
        return new BigInteger(bin2hex(random_bytes($length)), '16');
    }
}