<?php

/**
 * This file is part of phuria/zero-auth package.
 *
 * Copyright (c) 2016 Beniamin Jonatan Šimko
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Phuria\ZeroAuth\Tests\Protocol;

use phpseclib\Math\BigInteger;
use Phuria\ZeroAuth\HashGenerator\Sha1Generator;
use Phuria\ZeroAuth\Protocol\ProtocolHelper;
use Phuria\ZeroAuth\Protocol\KeyPair;
use Phuria\ZeroAuth\Protocol\ProtocolFacade;
use Phuria\ZeroAuth\RandomGenerator\DummyGenerator;
use Phuria\ZeroAuth\Tests\TestCase\ProtocolTestCase;

/**
 * @author Beniamin Jonatan Šimko <spam@simko.it>
 */
class ProtocolHelperTest extends \PHPUnit_Framework_TestCase
{
    const TEST_USER = 'phuria';
    const TEST_PASSWORD = '12345';

    use ProtocolTestCase;

    /**
     * @return ProtocolHelper
     */
    private function createDummyProtocolHelper()
    {
        $hashGenerator = new Sha1Generator();
        $randomGenerator = new DummyGenerator();
        $protocolFacade = new ProtocolFacade($hashGenerator, $randomGenerator);

        return ProtocolHelper::create1024($protocolFacade);
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleGenerateSalt()
    {
        $helper = $this->createDummyProtocolHelper();

        static::assertHexSame(DummyGenerator::DUMMY_VALUE, $helper->generateSalt()->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleGenerateClientKey()
    {
        $keyPair = $this->createDummyProtocolHelper()->generateClientKeyPair();

        static::assertInstanceOf(KeyPair::class, $keyPair);
        static::assertHexSame(DummyGenerator::DUMMY_VALUE, $keyPair->getPrivateKey()->toHex());
        static::assertHexSame(
            '979BCD54F8DE5172BF99AEA3633CD5EB7A4A6DB8622F60C8831C536DD4344D2B6A598F73454F5F4D30F3B20B85695745D0F7229D597A1B9076133A7199978FE73BA016EA9B2960C2AF1C8D1CBE77443096CB0E79FF8E4FA5B89736B6D2424B66E545B7E2B6B9173C1E2EF068CBFFEC8095BE523C15A97F4296B646C73EC40CD0',
            $keyPair->getPublicKey()->toHex()
        );
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleGenerateServerKey()
    {
        $verifier = new BigInteger('1234', 16);
        $keyPair = $this->createDummyProtocolHelper()->generateServerKeyPair($verifier);

        static::assertInstanceOf(KeyPair::class, $keyPair);
        static::assertHexSame(DummyGenerator::DUMMY_VALUE, $keyPair->getPrivateKey()->toHex());
        static::assertHexSame(
            '979BCD54F8DE5172BF99AEA3633CD5EB7A4A6DB8622F60C8831C536DD4344D2B6A598F73454F5F4D30F3B20B85695745D0F7229D597A1B9076133A7199978FE73BA016EA9B2960C2AF1C8D1CBE77443096CB0E79FF8E4FA5B89736B6D2424B66E545B7E2B6B9173C1E2EF1EE78AA783FCA1444DD2CE94042853535D1CCA4ED10',
            $keyPair->getPublicKey()->toHex()
        );
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeMultiplier()
    {
        $helper = $this->createDummyProtocolHelper();
        $multiplier = $helper->computeMultiplier($helper->getPrime(), $helper->getGeneratorModulo());

        static::assertInstanceOf(BigInteger::class, $multiplier);
        static::assertHexSame('156831CD39BFA246E6CA1F309E35F95961ECFC50', $multiplier->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeCredentialHash()
    {
        $helper = $this->createDummyProtocolHelper();
        $salt = $helper->generateSalt();
        $credentialHash = $this->createDummyProtocolHelper()
            ->computeCredentialsHash($salt, static::TEST_USER, static::TEST_PASSWORD);

        static::assertInstanceOf(BigInteger::class, $credentialHash);
        static::assertHexSame('32D5E11B30E27FD62F9C182136139055F98A517B', $credentialHash->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeVerifier()
    {
        $credentialHash = new BigInteger('1234', 16);
        $verifier = $this->createDummyProtocolHelper()->computeVerifier($credentialHash);

        static::assertInstanceOf(BigInteger::class, $verifier);
        static::assertHexSame(
            '55FA210FF4ACEEACF4CB070DB869AB63E0D728E1213C83521B58EF6F5A590C266A897E5511FA61EC8F76C97BB6A3B00BD48298B612A4F8905BBFF485381863C2099D40D3DB0A8A8AA13572005206E5E91B936DAADB18C4B21B8A6C62D3C723A517755CE3516DB530A9C1CF934F6EBCE35F10F701A1E732FC32A240DCA5A44A4E',
            $verifier->toHex()
        );
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeScrambling()
    {
        $key = new BigInteger('1234', 16);
        $scrambling = $this->createDummyProtocolHelper()->computeScrambling($key, $key);

        static::assertInstanceOf(BigInteger::class, $scrambling);
        static::assertHexSame('C129B324AEE662B04ECCF68BABBA85851346DFF9', $scrambling->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeServerSessionKey()
    {
        $dummyHash = new BigInteger('1234', 16);
        $key = $this->createDummyProtocolHelper()
            ->computeClientSessionKey($dummyHash, $dummyHash, $dummyHash, $dummyHash);

        static::assertInstanceOf(BigInteger::class, $key);
        static::assertHexSame('4415E3E3DA17AC703640B310DD5FCBCE02FBA717', $key->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldBeAbleComputeClientSessionKey()
    {
        $dummyHash = new BigInteger('1234', 16);
        $key = $this->createDummyProtocolHelper()
            ->computeServerSessionKey($dummyHash, $dummyHash, $dummyHash, $dummyHash);

        static::assertInstanceOf(BigInteger::class, $key);
        static::assertHexSame('49CC31DE082A9A7EDCBD1692808223BC27B59944', $key->toHex());
    }

    /**
     * @test
     * @small
     */
    public function shouldReturnGivenArguments()
    {
        $prime = new BigInteger('2', 10);
        $generatorModulo = new BigInteger('2', 10);

        $facade = new ProtocolFacade(new Sha1Generator(), new DummyGenerator());
        $helper = new ProtocolHelper($facade, $prime, $generatorModulo);

        static::assertSame($prime, $helper->getPrime());
        static::assertSame($generatorModulo, $helper->getGeneratorModulo());
        static::assertSame($facade, $helper->getFacade());
        static::assertInstanceOf(BigInteger::class, $helper->getMultiplier());
    }
}
