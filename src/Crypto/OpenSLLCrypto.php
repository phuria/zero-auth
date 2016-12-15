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

use Phuria\ZeroAuth\RandomGenerator\RandomGeneratorInterface;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class OpenSLLCrypto implements CryptoInterface
{
    /**
     * @var RandomGeneratorInterface
     */
    private $generator;

    /**
     * @param RandomGeneratorInterface $generator
     */
    public function __construct(RandomGeneratorInterface $generator)
    {
        $this->generator = $generator;
    }

    /**
     * @inheritdoc
     */
    public function supports($cipher)
    {
        return in_array($cipher, openssl_get_cipher_methods());
    }

    /**
     * @inheritdoc
     */
    public function generateIv($cipher)
    {
        $ivLength = openssl_cipher_iv_length($cipher);
        $rand = $this->generator->generate($ivLength / 2);

        return $rand->toHex();
    }

    /**
     * @inheritdoc
     */
    public function decrypt($data, $cipher, $sessionKey, $iv)
    {
        return openssl_decrypt($data, $cipher, $sessionKey, 0, $iv);
    }

    /**
     * @inheritdoc
     */
    public function encrypt($data, $cipher, $sessionKey, $iv)
    {
        return openssl_encrypt($data, $cipher, $sessionKey, 0, $iv);
    }
}