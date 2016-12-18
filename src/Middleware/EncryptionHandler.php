<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Middleware;

use Phuria\ZeroAuth\Crypto\CryptoInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Stream;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class EncryptionHandler
{
    /**
     * @var CryptoInterface
     */
    private $crypto;

    /**
     * @param CryptoInterface $crypto
     */
    public function __construct(CryptoInterface $crypto)
    {
        $this->crypto = $crypto;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param callable               $next
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        /** @var SessionInterface $session */
        $session = $request->getAttribute(SessionInterface::class);
        $sessionKey = $session->getSessionKey();

        $cryptoData = json_decode($request->getBody(), true);
        $decrypted = $this->crypto->decrypt(
            $cryptoData['data'],
            $cryptoData['cipher'],
            $sessionKey->toBytes(),
            $cryptoData['iv']
        );

        $stream = new Stream('php://memory', 'rw');
        $stream->write($decrypted);

        /** @var ResponseInterface $response */
        $response = $next($request->withBody($stream), $response);

        $cryptoData['iv'] = $this->crypto->generateIv($cryptoData['cipher']);
        $cryptoData['data'] = $this->crypto->encrypt(
            $response->getBody(),
            $cryptoData['cipher'],
            $sessionKey->toBytes(),
            $cryptoData['iv']
        );

        $stream = new Stream('php://memory', 'rw');
        $stream->write(json_encode($cryptoData));

        return $response->withBody($stream);
    }
}