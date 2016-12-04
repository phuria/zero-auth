<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Protocol;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\HashGenerator\HashGeneratorInterface;
use Phuria\ZeroAuth\RandomGenerator\RandomGeneratorInterface;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class ProtocolFacade
{
    /**
     * @var HashGeneratorInterface
     */
    private $hashGenerator;

    /**
     * @var RandomGeneratorInterface
     */
    private $randomGenerator;

    /**
     * @param HashGeneratorInterface   $hashGenerator
     * @param RandomGeneratorInterface $randomGenerator
     */
    public function __construct(HashGeneratorInterface $hashGenerator, RandomGeneratorInterface $randomGenerator)
    {
        $this->hashGenerator = $hashGenerator;
        $this->randomGenerator = $randomGenerator;
    }

    /**
     * @param mixed $data
     *
     * @return BigInteger
     */
    public function hash($data)
    {
        return new BigInteger($this->hashGenerator->generate($data), 16);
    }

    /**
     * @param int $length
     *
     * @return BigInteger
     */
    public function random($length = 64)
    {
        return $this->randomGenerator->generate($length);
    }
}