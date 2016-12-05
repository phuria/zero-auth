<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\TestCase;

use Phuria\ZeroAuth\HashGenerator\Sha1Generator;
use Phuria\ZeroAuth\Protocol\ProtocolFacade;
use Phuria\ZeroAuth\Protocol\ProtocolHelper;
use Phuria\ZeroAuth\RandomGenerator\RandomBytesGenerator;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
trait ProtocolTestCase
{
    /**
     * @return ProtocolHelper
     */
    public function createProtocolHelper()
    {
        $hashGenerator = new Sha1Generator();
        $randomGenerator = new RandomBytesGenerator();
        $facade = new ProtocolFacade($hashGenerator, $randomGenerator);

        return ProtocolHelper::create1024($facade);
    }

    /**
     * @param string $expected
     * @param string $actual
     */
    public static function assertHexSame($expected, $actual)
    {
        static::assertSame(strtoupper($expected), strtoupper($actual));
    }
}