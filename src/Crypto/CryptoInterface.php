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
interface CryptoInterface
{
    /**
     * @param string $cipher
     *
     * @return bool
     */
    public function supports($cipher);

    /**
     * @param string $cipher
     *
     * @return mixed
     */
    public function generateIv($cipher);

    /**
     * @param string $data
     * @param string $cipher
     * @param string $sessionKey
     * @param mixed  $iv
     *
     * @return string
     */
    public function decrypt($data, $cipher, $sessionKey, $iv);

    /**
     * @param string $data
     * @param string $cipher
     * @param string $sessionKey
     * @param mixed  $iv
     *
     * @return mixed
     */
    public function encrypt($data, $cipher, $sessionKey, $iv);
}