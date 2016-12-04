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
class Calculator
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
     * @return Calculator
     */
    public static function createDefault(ProtocolFacade $facade)
    {
        $prime = <<<PRIME
99497054337086473442435202604522816989643863571126408511774020575773849326355529
17868662949815133641650251664564169951681314039489794063656164654594775323230145
36035832232680856136472337680816457276690373943856965228203015358880418155595134
08036145123870584325525813950487109647770743827362571822870567643040184723115825
64559038631337706711263814925317184391478006513737344622240632295356912477148010
13631809664480998822924534523954282708757325363115392661151164907049401641924177
44919250000894727407937229829300578253427884494358459949535231819781361449649779
25294809990982164220748551480576828811558340914896987579052396187875312497268117
99442346410169600118157888474366101927045516370344725523198203365320145614120288
20492176940418377074274389149924303484945446105121267538061583299291707972378807
39501603076544065560175910937056452264798915612180427301226601178345110223008138
04019513835829871495782299408181815140463148193132063213759733367850235654431013
05633127610230549588655605951332351485641757542611227108073263889434409595976835
13741218702534963950440406165465375534916268062929055164415338276068186229467741
49890474919227957072109204378111367127944834964373559808334633295928381401578031
82055197821702739206310971006260383262542900044072533196137796552746439051760940
43008237564115012981796018302808101097878090244173368097771481354343875254613637
5675139915776
PRIME;

        $prime = new BigInteger(str_replace(PHP_EOL, '', $prime), '10');
        $generatorModulo = new BigInteger('2', 16);

        return new self($facade, $prime, $generatorModulo);
    }

    public function generateSalt()
    {
        return new BigInteger($this->facade->random(), '16');
    }

    /**
     * @param BigInteger $verifier
     *
     * @return KeyPair
     */
    public function generateServerKeyPair(BigInteger $verifier)
    {
        do {
            $serverPrivateKey = $this->facade->random();
            $powResult = $this->generatorModulo->powMod($serverPrivateKey, $this->prime);
            $serverPublicKey = $this->multiplier
                ->multiply($verifier)
                ->add($powResult)
                ->powMod(new BigInteger(1), $this->prime);
        } while ($serverPublicKey->powMod(new BigInteger(1), $this->prime)->equals(new BigInteger(0)));

        return new KeyPair($serverPrivateKey, $serverPublicKey);
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
     * @param BigInteger $prime
     * @param BigInteger $generatorModulo
     *
     * @return BigInteger
     */
    public function computeMultiplier(BigInteger $prime, BigInteger $generatorModulo)
    {
        $hash = $this->facade->hash($prime->toHex() . $generatorModulo->toHex());

        return new BigInteger($hash, 16);
    }

    /**
     * @param string $salt
     * @param string $username
     * @param string $password
     *
     * @return BigInteger
     */
    public function computeCredentialsHash($salt, $username, $password)
    {
        $hash = $this->facade->hash($salt . $username . $password);

        return new BigInteger($hash, 16);
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
        $hash = $this->facade->hash($publicClientKey->toHex() . $publicServerKey->toHex());

        return new BigInteger($hash, 16);
    }

    public function computeSessionKey(
        BigInteger $clientPublicKey,
        BigInteger $verifier,
        BigInteger $scrambling,
        BigInteger $serverPrivateKey
    ) {

    }
}