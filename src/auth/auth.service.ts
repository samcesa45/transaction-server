import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
// import { TwiloService } from 'src/twilo/twilo.service';
import {
  BiometricLoginDto,
  EnableBioMetricDto,
  RegisterDto,
  SetTransactionPinDto,
  TokenPairDto,
  UserLoginDto,
  VerifyOTPDto,
  VerifyTransactionPinDto,
} from './dto/authdto';
import bcrypt from 'bcrypt';
import { MailService } from 'src/mail/mail.service';
import { RedisService } from 'src/redis/redis.service';
import { NotificationService } from 'src/notification/notification.service';
import { BankingGateway } from 'src/bankinggateway/bankinggateway.gateway';
import { BiometricService } from 'src/biometric/biometric.service';
import { OtpPurpose, actionType, statusType  } from '@prisma/client';
const saltRounds = parseInt(process.env.HASH_SALT_ROUNDS ?? '10', 10);
const otpExpiryMins = parseInt(process.env.OTP_EXPIRY_MINUTES ?? '5', 10);

@Injectable()
export class AuthService {
  //token blacklist prefix for redis
  private readonly BLACKLIST_PREFIX = 'blacklist:token:';
  private readonly REFRESH_TOKEN_PREFIX = 'refresh:token:';
  private readonly SALT_ROUNDS = saltRounds;
  private readonly OTP_EXPIRY_MINUTES = otpExpiryMins;
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCK_DURATION_MINUTES = 30;
  private readonly SESSION_EXPIRY_DAYS = 30;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    // private twilioService: TwiloService,
    private mailService: MailService,
    // Add Redis for token blacklisting
    private redis: RedisService,
    private notificationService: NotificationService,
    private bankingGateway: BankingGateway,
    private biometricService: BiometricService,
  ) {}

  //registration (one-time email verification)
  async register(dto: RegisterDto) {
    //Check if user already exists
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email: dto.email }, { phoneNumber: dto.phoneNumber }],
      },
    });

    if (existingUser) {
      throw new BadRequestException(
        'Email or phone number already registered.',
      );
    }

    //Hash password
    const passwordHash = await bcrypt.hash(dto.password, this.SALT_ROUNDS);
    //create user
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        passwordHash,
        firstName: dto.firstName,
        lastName: dto.lastName,
        middleName: dto.middleName,
        phoneNumber: dto.phoneNumber,
        dateOfBirth: dto.dateOfBirth,
        isActive: false, //Activated after email verification
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
      },
    });

    //Register device
    await this.prisma.device.create({
      data: {
        userId: user.id,
        deviceId: dto.deviceId,
        deviceName: dto.deviceName || 'Unknown Device',
        deviceType: 'mobile',
      },
    });

    //send verification email (ONE TIME ONLY)
    const otp = this.generateOtp();
    await this.storeOTP(user.id, otp, OtpPurpose.email_verification);
    await this.mailService.sendOTPEmail(user.email, otp);

    return {
      message: 'Registration successful. Please verify your email.',
      userId: user.id,
      requiresVerification: true,
    };
  }

  //email verification (ONE-TIME)
  async verifyEmail(dto: VerifyOTPDto) {
    const isValid = await this.verifyOTP(
      dto.userId,
      dto.otp,
      OtpPurpose.email_verification,
    );

    if (!isValid) {
      throw new UnauthorizedException('Invalid or expired OTP');
    }

    //activate user account
    await this.prisma.user.update({
      where: { id: dto.userId },
      data: {
        emailVerified: true,
        isActive: true,
      },
    });

    return { message: 'Email verified successfully. You can now login.' };
  }

  //login (password - first time or new device)
  async login(dto: UserLoginDto, ipAddress?: string, userAgent?: string) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new NotFoundException('Invalid credentials');
    }

    // Check if account is locked
    if (user.isLocked) {
      const lockExpiry = new Date(user.lastFailedLogin!);
      lockExpiry.setMinutes(
        lockExpiry.getMinutes() + this.LOCK_DURATION_MINUTES,
      );

      if (new Date() < lockExpiry) {
        throw new UnauthorizedException(
          `Account locked. Try again after ${Math.ceil((lockExpiry.getTime() - Date.now()) / 60000)} minutes`,
        );
      }

      //unlock account
      await this.prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          isLocked: false,
          failedLoginAttempts: 0,
        },
      });
    }

    //verify password
    const isPasswordValid = await bcrypt.compare(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      await this.handleFailedLogin(user.id);
      throw new UnauthorizedException('Invalid credentials.');
    }

    //check if device exists
    let device = await this.prisma.device.findUnique({
      where: { deviceId: dto.deviceId },
    });

    //register new device if not exists
    if (!device) {
      device = await this.prisma.device.create({
        data: {
          userId: user.id,
          deviceId: dto.deviceId,
          deviceName: dto.deviceName || 'Unknown Device',
          deviceType: 'mobile',
          fcmToken: dto.fcmToken,
        },
      });
    } else {
      //update device info
      await this.prisma.device.update({
        where: { id: device.id },
        data: {
          lastUsed: new Date(),
          fcmToken: dto.fcmToken || device.fcmToken,
        },
      });
    }

    //reset failed attempts
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lastLogin: new Date(),
      },
    });

    //create session
    const tokens = await this.createSession(
      user.id,
      dto.deviceId,
      ipAddress,
      userAgent,
    );

    //log security event
    await this.logSecurityEvent(user.id, actionType.login, statusType.success, {
      deviceId: dto.deviceId,
      ipAddress,
    });

    //send login notification
    await this.notificationService.notifyLogin(
      user.id,
      dto.deviceName || 'Unknown Device',
      ipAddress,
    );

    //send security alert via Websoket
    this.bankingGateway.sendSecurityAlert(user.id, {
      type: 'login',
      message: `New login from ${dto.deviceName || 'Unknown Device'}`,
    });

    return {
      ...tokens,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        biometricEnabled: device.biometricEnabled,
        hasTransactionPin: !!user.transactionPin,
      },
      message: 'Login successful!',
    };
  }

  // BIOMETRIC LOGIN (SUBSEQUENT LOGINS)
  async biometricLogin(dto: BiometricLoginDto, ipAddress?: string) {
    //get device and user
    const device = await this.prisma.device.findUnique({
      where: { deviceId: dto.deviceId },
      include: { User: true },
    });

    if (!device || !device.biometricEnabled) {
      throw new UnauthorizedException(
        'Biometric authentication not enabled for this device.',
      );
    }

    //verify biometric signature
    const isValid = await this.biometricService.verifyBiometricSignature(
      dto.deviceId,
      dto.challenge,
      dto.signature,
    );

    if (!isValid) {
      throw new UnauthorizedException('Biometric authentication failed');
    }

    //create session
    const tokens = await this.createSession(
      device.userId,
      dto.deviceId,
      ipAddress,
    );

    //update device last used
    await this.prisma.device.update({
      where: { id: device.id },
      data: { lastUsed: new Date() },
    });

    //log security event
    await this.logSecurityEvent(
      device.userId,
      actionType.biometric_login,
      statusType.success,
      {
        deviceId: dto.deviceId,
      },
    );

    return {
      ...tokens,
      user: {
        id: device.User.id,
        email: device.User.email,
        firstName: device.User.firstName,
        lastName: device.User.lastName,
      },
      message: 'Login successful',
    };
  }

  //get biometric challenge
  async getBiometricChallenge(deviceId: string) {
    const challenge = await this.biometricService.generateChallenge(deviceId);
    return { challenge };
  }

  async getUserDevices(userId: string) {
    return this.prisma.device.findMany({
      where: { userId, isActive: true },
      select: {
        id: true,
        deviceId: true,
        deviceName: true,
        biometricEnabled: true,
        lastUsed: true,
        createdAt: true,
      },
      orderBy: { lastUsed: 'desc' },
    });
  }

  async removeDevice(userId: string, deviceId: string) {
    await this.prisma.device.updateMany({
      where: { userId, deviceId },
      data: {
        isActive: false,
        biometricEnabled: false,
      },
    });

    //invalidate sessions for this device
    await this.prisma.session.updateMany({
      where: { userId, deviceId },
      data: { isActive: false },
    });

    return { message: 'Device removed successfully' };
  }

  async getSecurityLogs(userId: string, limit: number = 50) {
    return this.prisma.securityLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      select: {
        id: true,
        action: true,
        status: true,
        metadata: true,
        createdAt: true,
      },
    });
  }

  //enable biometric (after first login)
  async enableBiometric(userId: string, dto: EnableBioMetricDto) {
    const device = await this.prisma.device.findFirst({
      where: {
        userId,
        deviceId: dto.deviceId,
      },
    });

    if (!device) {
      throw new NotFoundException('Device not found');
    }

    await this.prisma.device.update({
      where: { id: device.id },
      data: {
        biometricEnabled: true,
      },
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        biometricEnabled: true,
        biometricPublicKey: dto.biometricPublicKey,
      },
    });

    return { message: 'Biometric authentication enabled' };
  }

  // TRANSACTION PIN (FOR TRANSFERS)
  async setTransactionPin(userId: string, dto: SetTransactionPinDto) {
    if (dto.transactionPin !== dto.confirmPin) {
      throw new BadRequestException('Pins do not match');
    }

    const pinHash = await bcrypt.hash(dto.transactionPin, this.SALT_ROUNDS);

    await this.prisma.user.update({
      where: { id: userId },
      data: { transactionPin: pinHash },
    });

    return { message: 'Transaction PIN set successfully' };
  }

  async verifyTransactionPin(userId: string, dto: VerifyTransactionPinDto) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { transactionPin: true },
    });

    if (!user?.transactionPin) {
      throw new BadRequestException('Transaction PIN not set');
    }

    const isValid = await bcrypt.compare(
      dto.transactionPin,
      user.transactionPin,
    );

    if (!isValid) {
      throw new UnauthorizedException('Invalid PIN');
    }

    return { valid: true };
  }

  async updateFcmToken(userId: string, deviceId: string, fcmToken: string) {
    await this.prisma.device.updateMany({
      where: { userId, deviceId },
      data: { fcmToken }
    });

    return {
      message: 'FCM token updated successfully'
    }
  }

  // SESSION MANAGEMENT
  private async createSession(
    userId: string,
    deviceId: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const payload = { sub: userId, deviceId };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: process.env.JWT_SECRET_KEY,
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      expiresIn: '30d',
      secret: process.env.JWT_REFRESH_SECRET_KEY,
    });

    //store session in database
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.SESSION_EXPIRY_DAYS);

    await this.prisma.session.create({
      data: {
        userId,
        deviceId,
        refreshToken,
        accessToken,
        ipAddress,
        userAgent,
        expiresAt,
      },
    });

    return { accessToken, refreshToken };
  }

  async refreshAccessToken(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    try {
      //verify refresh token
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET_KEY,
      });

      //verify session exists and is active
      const session = await this.prisma.session.findFirst({
        where: {
          refreshToken,
          isActive: true,
          expiresAt: { gt: new Date() },
        },
      });

      if (!session) {
        throw new UnauthorizedException('Invalid or expired session');
      }

      const userId = payload.sub;

      //check if token is blacklisted
      if (await this.isTokenBlacklisted(refreshToken)) {
        throw new UnauthorizedException('Token has been revoked');
      }

      //check if user logged out from all devices
      if (await this.hasLoggedOutAll(userId, payload.iat)) {
        throw new UnauthorizedException('Session expired. Please login again.');
      }

      //verify if user still exists and is active
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, isActive: true },
      });

      if (!user || !user.isActive) {
        throw new UnauthorizedException('User not found or inactive');
      }

      //Generate new access token
      const newAccessToken = await this.jwtService.signAsync(
        { sub: payload.sub, deviceId: payload.deviceId },
        {
          expiresIn: '15m',
          secret: process.env.JWT_SECRET_KEY,
        },
      );

      //Generate new refreshToken
      const newRefreshToken = await this.jwtService.signAsync(
        { sub: userId },
        {
          expiresIn: '7d',
          secret: process.env.JWT_REFRESH_SECRET_KEY,
        },
      );
      //Blacklist the old refresh token
      await this.redis.get(`${this.BLACKLIST_PREFIX}${refreshToken}`);

      // update session
      await this.prisma.session.update({
        where: { id: session.id },
        data: {
          accessToken: newAccessToken,
          lastActivity: new Date(),
        },
      });
      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }
  // END OF SESSION MANAGEMENT

  async logout(userId: string, deviceId: string) {
    await this.prisma.session.updateMany({
      where: { userId, deviceId, isActive: true },
      data: { isActive: false },
    });

    await this.logSecurityEvent(userId, actionType.logout, statusType.success, {
      deviceId,
    });

    return { message: 'Logout successful' };
  }

  async logoutAllDevices(userId: string) {
    await this.prisma.session.updateMany({
      where: { userId, isActive: true },
      data: { isActive: false },
    });

    await this.logSecurityEvent(
      userId,
      actionType.logout_all,
      statusType.success,
      {},
    );

    return { message: 'Logged out from all devices' };
  }

  // HELPER METHODS
  private async handleFailedLogin(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    const failedAttempts = (user?.failedLoginAttempts || 0) + 1;

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginAttempts: failedAttempts,
        lastFailedLogin: new Date(),
        isLocked: failedAttempts >= this.MAX_LOGIN_ATTEMPTS,
      },
    });

    if (failedAttempts >= this.MAX_LOGIN_ATTEMPTS) {
      await this.logSecurityEvent(
        userId,
        actionType.account_locked,
        statusType.success,
        {
          reason: 'too_many_failed_attempts',
        },
      );
    }
  }

  private generateOtp(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  private async storeOTP(userId: string, otp: string, purpose: OtpPurpose) {
    const otpHash = await bcrypt.hash(otp, this.SALT_ROUNDS);
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);

    await this.prisma.oTP.create({
      data: {
        userId,
        otpHash,
        purpose,
        expiresAt,
      },
    });
  }

  private async verifyOTP(
    userId: string,
    otp: string,
    purpose: OtpPurpose,
  ): Promise<boolean> {
    const otpRecord = await this.prisma.oTP.findFirst({
      where: {
        userId,
        purpose,
        verified: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!otpRecord) return false;

    //check attempts
    if (otpRecord.attempts >= 3) {
      return false;
    }

    const isValid = await bcrypt.compare(otp, otpRecord.otpHash);

    if (!isValid) {
      await this.prisma.oTP.update({
        where: { id: otpRecord.id },
        data: { attempts: { increment: 1 } },
      });
      return false;
    }

    //mark as verified
    await this.prisma.oTP.update({
      where: { id: otpRecord.id },
      data: { verified: true },
    });

    return true;
  }

  private async verifyBiometricToken(
    token: string,
    userId: string,
  ): Promise<boolean> {
    // In production, verify the JWT signed by the device using the user's biometric public key
    // For now, simple validation
    try {
      const payload = this.jwtService.verify(token, {
        secret: process.env.BIOMETRIC_SECRET_KEY,
      });
      return payload.sub === userId;
    } catch (error) {
      return false;
    }
  }

  private async logSecurityEvent(
    userId: string,
    action: actionType,
    status: statusType,
    metadata: any,
  ) {
    await this.prisma.securityLog.create({
      data: {
        userId,
        action,
        status,
        metadata,
        deviceId: metadata.deviceId,
        ipAddress: metadata.ipAddress,
      },
    });
  }
  // END OF HELPER METHODS

  async generateTokens(userId: string): Promise<TokenPairDto> {
    const payload = { sub: userId };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        expiresIn: '15m',
        secret: process.env.JWT_SECRET_KEY,
      }),
      this.jwtService.signAsync(payload, {
        expiresIn: '7d',
        secret: process.env.JWT_REFRESH_SECRET_KEY,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  async logoutAll(userId: string) {
    try {
      //remove all refresh tokens for user
      await this.redis.del(`${this.REFRESH_TOKEN_PREFIX}${userId}`);

      //add user to global logout list with timestamp
      //this allows checking if tokens were issued before logout
      const logoutTimestamp = Date.now();
      await this.redis.setWithExpiry(
        `logout:all:${userId}`,
        logoutTimestamp.toString(),
        604800, //7 days (max refresh token life)
      );
      return { message: 'Logged out from all devices' };
    } catch (error) {
      throw new BadRequestException('Logout from all devices failed');
    }
  }

  /**
   *
   * Check if token is blacklisted (call this in your AuthGuard)
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    const result = await this.redis.get(`${this.BLACKLIST_PREFIX}${token}`);
    return result !== null;
  }

  /**
   *
   * Check if user has logged out from all devices after token was issued
   */
  async hasLoggedOutAll(
    userId: string,
    tokenIssuedAt: number,
  ): Promise<boolean> {
    const logoutTimestamp = await this.redis.get(`logout:all:${userId}`);
    if (!logoutTimestamp) return false;

    return parseInt(logoutTimestamp) > tokenIssuedAt * 1000; // Convert to ms
  }

  /**
   *
   * Store refresh token for user (allows single active session if desired)
   */

  private async storeRefreshToken(userId: string, refreshToken: string) {
    await this.redis.setex(
      `${this.REFRESH_TOKEN_PREFIX}${userId}`,
      604800, //7 days
      refreshToken,
    );
  }

  /**
   *
   * Resend OTP for 2FA
   */
  async resendOtp(userId: string, purpose: OtpPurpose) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    //Rate limiting: prevent OTP spam
    // const now = new Date();
    // if (user.lastLogin) {
    //   const timeSinceLastAttempt = now.getTime() - user.lastLogin.getTime();
    //   if (timeSinceLastAttempt < 60000) {
    //     //1 minute
    //     throw new BadRequestException(
    //       `Please wait ${Math.ceil((60000 - timeSinceLastAttempt) / 1000)} seconds before requesting a new OTP`,
    //     );
    //   }
    // }

    //Generate new OTP
    const otp = this.generateOtp();
    await this.storeOTP(userId, otp, purpose);
    await this.mailService.sendOTPEmail(user.email, otp);

    return {
      message: 'New OTP sent',
      expiresIn: otpExpiryMins * 60,
    };
  }
}
