<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\Protocol;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\HashGenerator\Sha512Generator;
use Phuria\ZeroAuth\Protocol\Calculator;
use Phuria\ZeroAuth\Protocol\KeyPair;
use Phuria\ZeroAuth\Protocol\ProtocolFacade;
use Phuria\ZeroAuth\RandomGenerator\RandomBytesGenerator;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class CalculatorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return Calculator
     */
    private function createTestCalculator()
    {
        $hashGenerator = new Sha512Generator();
        $randomGenerator = new RandomBytesGenerator();
        $facade = new ProtocolFacade($hashGenerator, $randomGenerator);

        return Calculator::createDefault($facade);
    }

    /**
     * @test
     * @small
     */
    public function canCreateClientKey()
    {
        $calculator = $this->createTestCalculator();
        $keyPair = $calculator->generateClientKeyPair();

        static::assertInstanceOf(KeyPair::class, $keyPair);
        static::assertNotEmpty($keyPair->getPublicKey()->toString());
        static::assertNotEmpty($keyPair->getPrivateKey()->toString());
    }

    /**
     * @test
     * @small
     */
    public function canCreateServerKey()
    {
        $calculator = $this->createTestCalculator();
        $keyPair = $calculator->generateServerKeyPair(new BigInteger('1'));

        static::assertInstanceOf(KeyPair::class, $keyPair);
        static::assertNotEmpty($keyPair->getPublicKey()->toString());
        static::assertNotEmpty($keyPair->getPrivateKey()->toString());
    }
}
