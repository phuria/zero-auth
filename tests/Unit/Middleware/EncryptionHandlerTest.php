<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\Unit\Middleware;

use Phuria\ZeroAuth\Crypto\DummyCrypto;
use Phuria\ZeroAuth\Middleware\EncryptionHandler;
use Zend\Diactoros\Request;
use Zend\Diactoros\Response;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class EncryptionHandlerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return EncryptionHandler
     */
    private function createDummyHandler()
    {
        $crypto = new DummyCrypto();

        return new EncryptionHandler($crypto);
    }

    /**
     * @test
     * @small
     */
    public function shouldNotModifyResponse()
    {
        $request = new Request();
        $response = new Response();

        $handler = $this->createDummyHandler();
        $returnedResponse = $handler($request, $response, function (Request $request, Response $response) {
            return $response;
        });

        static::assertSame($returnedResponse, $response);
    }
}
