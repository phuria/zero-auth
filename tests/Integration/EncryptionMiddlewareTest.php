<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\Integration;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\Crypto\OpenSLLCrypto;
use Phuria\ZeroAuth\Middleware\EncryptionHandler;
use Phuria\ZeroAuth\Middleware\SessionInterface;
use Phuria\ZeroAuth\RandomGenerator\RandomBytesGenerator;
use Phuria\ZeroAuth\Tests\Helper\Session;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Stream;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class EncryptionMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    const TEST_CIPHER = 'aes-128-cbc';
    const TEST_SESSION_KEY = '4415E3E3DA17AC703640B310DD5FCBCE02FBA717';

    /**
     * @test
     * @small
     */
    public function shouldCryptoRequestAndResponse()
    {
        $rand = new RandomBytesGenerator();
        $crypto = new OpenSLLCrypto($rand);
        $handler = new EncryptionHandler($crypto);
        $sessionKey = new BigInteger(static::TEST_SESSION_KEY, 16);

        $requestData = json_encode([
            'iv'     => $iv = $crypto->generateIv(static::TEST_CIPHER),
            'cipher' => static::TEST_CIPHER,
            'data'   => $crypto->encrypt('foo', static::TEST_CIPHER, $sessionKey->toBytes(), $iv)
        ]);

        $stream = new Stream('php://memory', 'rw');
        $stream->write($requestData);

        $session = new Session();
        $session->setSessionKey($sessionKey);

        $request = (new ServerRequest())
            ->withAttribute(SessionInterface::class, $session)
            ->withBody($stream)
            ->withHeader('Content-Type', 'application/zero-auth');

        $response = new Response();

        $response = $handler($request, $response, function (RequestInterface $request, ResponseInterface $response) {
              $this->assertSame('foo', $request->getBody()->__toString());

              $stream = new Stream('php://memory', 'rw');
              $stream->write('boo');

              return $response->withBody($stream);
        });

        $responseData = json_decode($response->getBody(), true);

        static::assertSame('boo', $crypto->decrypt(
            $responseData['data'],
            static::TEST_CIPHER,
            $sessionKey->toBytes(),
            $responseData['iv']
        ));
    }
}