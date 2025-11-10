import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { RedisService } from 'src/redis/redis.service';
import * as crypto from 'crypto';

@Injectable()
export class BiometricService {
  constructor(
    private prisma: PrismaService,
    private redis: RedisService,
  ) {}

  /**
   * Generate a challenge for biometric authentication
   * The mobile app will sign this challenge with the device's secure enclave
   */
  async generateChallenge(deviceId: string): Promise<string> {
    const challenge = crypto.randomBytes(32).toString('base64');

    //store challenge in redis with 5 minutes expiry
    await this.redis.setex(`biometric:challenge:${deviceId}`, 300, challenge);
    return challenge;
  }

  /**
   * Verify biometric signature
   * The mobile app signs the challenge with device's private key
   * We verify using the stored public key
   */

  async verifyBiometricSignature(
    deviceId: string,
    challenge: string,
    signature: string,
  ): Promise<boolean> {

    // Verify challenge matches what we sent
    const storedChallenge = await this.redis.get(
      `biometric:challenge:${deviceId}`,
    );

    if (!storedChallenge || storedChallenge !== challenge) {
      throw new UnauthorizedException('Invalid or expired challenge');
    }

    //get device public key
    const device = await this.prisma.device.findUnique({
      where: { deviceId },
      include: { User: true },
    });

    if (!device || !device.User.biometricPublicKey) {
      throw new UnauthorizedException('Biometric not configured');
    }

    //verify signature using RSA public key
    try {
      const verify = crypto.createVerify('RSA-SHA256');
      verify.update(challenge);
      verify.end();

      const publicKey = crypto.createPublicKey({
        key: device.User.biometricPublicKey,
        format: 'pem',
        type:'spki'
      });

      const isValid = verify.verify(
        publicKey,
        signature,
        'base64',
      );

      //delete challenge after use (prevent replay attacks)
      if(isValid){
        await this.redis.del(`biometric:challenge:${deviceId}`);
      }

      return isValid;

    } catch (error) {
      console.error('Biometric verification error:', error);
      return false;
    }
  }

  /**
   * Register biometric public key from device
   */
  async registerBiometricKey(
    userId: string,
    deviceId: string,
    publicKeyPem: string,
  ): Promise<void> {
    //validate public key format
    if (!this.isValidPublicKey(publicKeyPem)) {
      throw new UnauthorizedException('Invalid public key format');
    }
    
    //store in database
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        biometricPublicKey: publicKeyPem,
        biometricEnabled: true,
      },
    });

    await this.prisma.device.updateMany({
      where: { userId, deviceId },
      data: {
        biometricEnabled: true,
      },
    });
  }

  private isValidPublicKey(key: string): boolean {
    try {
      //Validate RSA public key format
      crypto.createPublicKey({
        key: key,
        format: 'pem',
        type: 'spki',
      });
      return true;
    } catch (error) {
        throw new UnauthorizedException('Invalid public key format');
    }
  }
}
