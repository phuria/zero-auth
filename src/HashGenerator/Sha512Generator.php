<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\HashGenerator;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class Sha512Generator implements HashGeneratorInterface
{
    /**
     * @inheritdoc
     */
    public function generate($data)
    {
        return hash('sha512', $data);
    }
}