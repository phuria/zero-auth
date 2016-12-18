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
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var SessionInterface
     */
    private $session;

    /**
     * @param ProtocolHelper        $helper
     * @param UserProviderInterface $provider
     * @param SessionInterface      $session
     */
    public function __construct(
        ProtocolHelper $helper,
        UserProviderInterface $provider,
        SessionInterface $session
    ) {
        $this->helper = $helper;
        $this->userProvider = $provider;
        $this->session = $session;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response)
    {
        $userProvider = $this->userProvider;
        $session = $this->session;

        $exchangeData = json_decode($request->getBody(), true);

        $username = $exchangeData['username'];
        $verifier = $userProvider->findVerifierByUsername($username);
        $exchangeData['verifier'] = $verifier->toHex();
        $salt = $this->userProvider->findSaltByUsername($username);
        $exchangeData['salt'] = $salt->toHex();
        $clientPublicKey = new BigInteger($exchangeData['clientPublicKey'], 16);
        $stream = new Stream('php://memory');

        if (false === array_key_exists('clientProof', $exchangeData)) {
            $keyPair = $this->helper->generateServerKeyPair($verifier);
            $session->setServerKeyPair($keyPair);
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