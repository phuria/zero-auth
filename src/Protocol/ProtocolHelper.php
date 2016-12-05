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

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class ProtocolHelper
{
    /**
     * @var ProtocolFacade
     */
    private $facade;

    /**
     * @var BigInteger
     */
    private $prime;

    /**
     * @var BigInteger
     */
    private $generatorModulo;

    /**
     * @var BigInteger
     */
    private $multiplier;

    /**
     * @param ProtocolFacade $facade
     * @param BigInteger     $prime
     * @param BigInteger     $generatorModulo
     */
    public function __construct(ProtocolFacade $facade, BigInteger $prime, BigInteger $generatorModulo)
    {
        $this->facade = $facade;
        $this->prime = $prime;
        $this->generatorModulo = $generatorModulo;
        $this->multiplier = $this->computeMultiplier($this->prime, $this->generatorModulo);
    }

    /**
     * @param ProtocolFacade $facade
     *
     * @return ProtocolHelper
     */
    public static function create1024(ProtocolFacade $facade)
    {
        $prime = <<<PRIME
EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
FD5138FE 8376435B 9FC61D2F C0EB06E3  
PRIME;

        return static::create($facade, $prime, '2');
    }

    /**
     * @param ProtocolFacade $facade
     *
     * @return ProtocolHelper
     */
    public static function create1536(ProtocolFacade $facade)
    {
        $prime = <<<PRIME
9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
PRIME;

        return static::create($facade, $prime, '2');
    }

    /**
     * @param ProtocolFacade $facade
     * @param string         $primeHex
     * @param string         $generatorHex
     *
     * @return ProtocolHelper
     */
    private static function create(ProtocolFacade $facade, $primeHex, $generatorHex)
    {
        $prime = new BigInteger(str_replace([PHP_EOL, ' '], ['', ''], $primeHex), '16');
        $generatorModulo = new BigInteger($generatorHex, 16);

        return new self($facade, $prime, $generatorModulo);
    }

    /**
     * @return BigInteger
     */
    public function generateSalt()
    {
        return $this->facade->random();
    }

    /**
     * @return KeyPair
     */
    public function generateClientKeyPair()
    {
        $clientPrivateKey = $this->facade->random();
        $clientPublicKey = $this->generatorModulo->powMod($clientPrivateKey, $this->prime);

        return new KeyPair($clientPrivateKey, $clientPublicKey);
    }

    /**
     * @param BigInteger $verifier
     *
     * @return KeyPair
     */
    public function generateServerKeyPair(BigInteger $verifier)
    {
        $bigOne = new BigInteger(1);
        $bigZero = new BigInteger(0);

        do {
            $serverPrivateKey = $this->facade->random();
            $serverPublicKey = $this->multiplier->multiply($verifier)->add(
                $this->generatorModulo->powMod($serverPrivateKey, $this->prime)
            )->powMod($bigOne, $this->prime);
        } while ($serverPublicKey->powMod($bigOne, $this->prime)->equals($bigZero));

        return new KeyPair($serverPrivateKey, $serverPublicKey);
    }

    /**
     * @param BigInteger $prime
     * @param BigInteger $generatorModulo
     *
     * @return BigInteger
     */
    public function computeMultiplier(BigInteger $prime, BigInteger $generatorModulo)
    {
        return $this->facade->hash($prime->toHex() . $generatorModulo->toHex());
    }

    /**
     * @param BigInteger $salt
     * @param string     $username
     * @param string     $password
     *
     * @return BigInteger
     */
    public function computeCredentialsHash(BigInteger $salt, $username, $password)
    {
        $saltHex = $salt->toHex();
        $saltPrefix = 0 !== strlen($saltHex) % 2 ? '0' : '';
        $usernamePassword = $this->facade->hash("{$username}:{$password}");

        return $this->facade->hash($saltPrefix . $saltHex . $usernamePassword->toHex());
    }

    /**
     * @param BigInteger $credentialsHash
     *
     * @return BigInteger
     */
    public function computeVerifier(BigInteger $credentialsHash)
    {
        return $this->generatorModulo->powMod($credentialsHash, $this->prime);
    }

    /**
     * @param BigInteger $publicClientKey
     * @param BigInteger $publicServerKey
     *
     * @return BigInteger
     */
    public function computeScrambling(BigInteger $publicClientKey, BigInteger $publicServerKey)
    {
        return $this->facade->hash($publicClientKey->toHex() . $publicServerKey->toHex());
    }

    /**
     * @param BigInteger $clientPublicKey
     * @param BigInteger $verifier
     * @param BigInteger $scrambling
     * @param BigInteger $serverPrivateKey
     *
     * @return BigInteger
     * @throws \Exception
     */
    public function computeServerSessionKey(
        BigInteger $clientPublicKey,
        BigInteger $verifier,
        BigInteger $scrambling,
        BigInteger $serverPrivateKey
    ) {
        $bigOne = new BigInteger(1);
        $bigZero = new BigInteger(0);

        if ($clientPublicKey->powMod($bigOne, $this->prime)->equals($bigZero)) {
            throw new \Exception();
        }

        if ($serverPrivateKey->powMod($bigOne, $this->prime)->equals($bigZero)) {
            throw new \Exception();
        }

        $raw = $clientPublicKey
            ->multiply(
                $verifier->powMod($scrambling, $this->prime)
            )
            ->powMod($serverPrivateKey, $this->prime);

        return $this->facade->hash($raw->toHex());
    }

    /**
     * @param BigInteger $credentialHash
     * @param BigInteger $serverPublicKey
     * @param BigInteger $clientPrivateKey
     * @param BigInteger $scrambling
     *
     * @return BigInteger
     */
    public function computeClientSessionKey(
        BigInteger $credentialHash,
        BigInteger $serverPublicKey,
        BigInteger $clientPrivateKey,
        BigInteger $scrambling
    ) {
        $raw = $serverPublicKey->subtract(
            $this->multiplier->multiply(
                $this->generatorModulo->powMod($credentialHash, $this->prime)
            )
        )->powMod(
            $clientPrivateKey->add($scrambling->multiply($credentialHash)),
            $this->prime
        );

        return $this->facade->hash($raw->toHex());
    }

    /**
     * @return ProtocolFacade
     */
    public function getFacade()
    {
        return $this->facade;
    }

    /**
     * @return BigInteger
     */
    public function getPrime()
    {
        return $this->prime;
    }

    /**
     * @return BigInteger
     */
    public function getGeneratorModulo()
    {
        return $this->generatorModulo;
    }

    /**
     * @return BigInteger
     */
    public function getMultiplier()
    {
        return $this->multiplier;
    }
}