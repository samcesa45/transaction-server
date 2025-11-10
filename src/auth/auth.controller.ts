import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Ip,
  Param,
  Post,
  Req,
  Request,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  BiometricLoginDto,
  EnableBioMetricDto,
  RefreshTokenDto,
  RegisterDto,
  SetTransactionPinDto,
  TokenPairDto,
  UserLoginDto,
  VerifyOTPDto,
  VerifyTransactionPinDto,
} from './dto/authdto';
import { JwtAuthGuard } from './jwt-auth.guard';
import { OtpPurpose } from '@prisma/client';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.ACCEPTED)
  async verifyEmail(@Body() dto: VerifyOTPDto) {
    return this.authService.verifyEmail(dto);
  }

  @Post('resend-otp')
  @HttpCode(HttpStatus.OK)
  async resendOTP(@Body() body: { userId: string; purpose: OtpPurpose }) {
    return this.authService.resendOtp(body.userId, body.purpose);
  }

  @Post('login')
  @HttpCode(HttpStatus.ACCEPTED)
  async login(
    @Body() dto: UserLoginDto,
    @Ip() ipAddress: string,
    @Headers('user-agent') userAgent: string,
  ) {
    return this.authService.login(dto, ipAddress, userAgent);
  }

  @Post('biometric-challenge')
  @HttpCode(HttpStatus.OK)
  async getBiometricChallenge(@Body() body: {deviceId:string}){
    return this.authService.getBiometricChallenge(body.deviceId)
  }

  @Post('biometric-login')
  @HttpCode(HttpStatus.ACCEPTED)
  async biometricLogin(
    @Body() dto: BiometricLoginDto,
    @Ip() ipAddress: string,
  ): Promise<TokenPairDto> {
    return this.authService.biometricLogin(dto, ipAddress);
  }

  @Post('enable-biometric')
  @UseGuards(JwtAuthGuard)
  async enableBiometric(@Request() req, @Body() dto: EnableBioMetricDto) {
    return this.authService.enableBiometric(req.user.sub, dto);
  }

  @Post('set-transaction-pin')
  @UseGuards(JwtAuthGuard)
  async setTransactionPin(@Request() req, @Body() dto: SetTransactionPinDto) {
    return this.authService.setTransactionPin(req.user.sub, dto);
  }

  @Post('verify-transaction-pin')
  @UseGuards(JwtAuthGuard)
  async verifyTransactionPin(
    @Request() req,
    @Body() dto: VerifyTransactionPinDto,
  ) {
    return this.authService.verifyTransactionPin(req.user.sub, dto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() dto: RefreshTokenDto) {
    return this.authService.refreshAccessToken(dto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(@Request() req: any, @Body() body: { deviceId: string }) {
    const userId = req?.user?.sub;
    if (!userId) throw new UnauthorizedException('Invalid token');
  if (!body?.deviceId) throw new BadRequestException('Device ID required');
    return this.authService.logout(userId, body.deviceId);
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logoutAllDevices(@Request() req: any) {
    const userId = req.user.sub;
    return this.authService.logoutAllDevices(userId);
  }

  @Get('devices')
  @UseGuards(JwtAuthGuard)
  async getUserDevices(@Request() req) {
    return this.authService.getUserDevices(req.user.sub);
  }

  @Delete('devices/:deviceId')
  @UseGuards(JwtAuthGuard)
  async removeDevice(@Request() req, @Param('deviceId') deviceId: string) {
    return this.authService.removeDevice(req.use.sub, deviceId);
  }

  @Get('security-logs')
  @UseGuards(JwtAuthGuard)
  async getSecurityLogs(@Request() req) {
    return this.authService.getSecurityLogs(req.user.sun);
  }

  @Post('update-fcm-token')
  @UseGuards(JwtAuthGuard)
  async updateFcmToken(@Request() req, @Body() body: { deviceId: string; fcmToken: string }){
    return this.authService.updateFcmToken(
      req.user.sub,
      body.deviceId,
      body.fcmToken
    )
  }

  private extractToken(request: any): string {
    const [, token] = request.headers.authorization?.split(' ') ?? [];
    return token;
  }
}
