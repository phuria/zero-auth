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
interface RandomGeneratorInterface
{
    /**
     * @param int $length
     *
     * @return BigInteger
     */
    public function generate($length = 64);
}