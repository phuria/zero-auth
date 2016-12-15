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

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\Protocol\ProtocolHelper;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zend\Diactoros\Stream;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class ServerExchangeHandler
{
    /**
     * @var ProtocolHelper
     */
    private $helper;

    /**
     * @param ProtocolHelper $helper
     */
    public function __construct(ProtocolHelper $helper)
    {
        $this->helper = $helper;
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
        /** @var UserProviderInterface $userProvider */
        $userProvider = $request->getAttribute(UserProviderInterface::class);
        /** @var SessionInterface $session */
        $session = $request->getAttribute(SessionInterface::class);

        $exchangeData = json_decode($request->getBody(), true);

        $username = $exchangeData['username'];
        $verifier = $userProvider->findVerifierByUsername($username);
        $clientPublicKey = new BigInteger($exchangeData['clientPublicKey'], 16);

        $stream = new Stream('php://memory');

        if (false === array_key_exists('salt', $exchangeData)) {
            $salt = $this->helper->generateSalt();
            $keyPair = $this->helper->generateServerKeyPair($verifier);

            $session->setServerKeyPair($keyPair);

            $exchangeData['salt'] = $salt->toHex();
            $exchangeData['serverPublicKey'] = $keyPair->getPublicKey()->toHex();

            return $response->withBody($stream->write(json_encode($exchangeData)));
        }

        $keyPair = $session->getServerKeyPair();
        $scrambling = $this->helper->computeScrambling($clientPublicKey, $keyPair->getPublicKey());

        $sessionKey = $this->helper->computeServerSessionKey(
            $clientPublicKey,
            $verifier,
            $scrambling,
            $keyPair->getPrivateKey()
        );

        $clientProof = new BigInteger($exchangeData['clientProof'], 16);
        $salt = new BigInteger($exchangeData['salt'], 16);
        $expectedClientProof = $this->helper->computeClientProof(
            $username,
            $salt,
            $clientPublicKey,
            $keyPair->getPrivateKey(),
            $sessionKey
        );

        if (false === $clientProof->equals($expectedClientProof)) {
            return $response->withStatus(401);
        }

        $exchangeData['serverProof'] = $this->helper->computeServerProof(
            $clientPublicKey,
            $clientProof,
            $sessionKey
        )->toHex();

        $session->setSessionKey($sessionKey);

        return $response->withBody($stream->write(json_encode($exchangeData)));
    }
}