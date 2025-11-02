import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RefreshTokenDto, RegisterDto, TokenPairDto, TwoFactorRequiredDto, TwoFactorVerifyDto, UpdateDto, UserLoginDto } from './dto/authdto';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() dto: RegisterDto) {
       return this.authService.register(dto);
    }

    @Post('login')
    @HttpCode(HttpStatus.ACCEPTED)
    async login(@Body() dto:UserLoginDto): Promise<TokenPairDto | TwoFactorRequiredDto> {
        const result = await this.authService.login(dto);

        // Check if the service returned tokens (meaning 2FA is complete/disabled) or the 2FA trigger message
        if('accessToken' in result){
            return result as unknown as TokenPairDto;
        }

        // Return the 2FA trigger response
        return result as TwoFactorRequiredDto;
    }

    @Post('verify-2fa')
    @HttpCode(HttpStatus.OK)
    async verifyTwoFactor(@Body() dto: TwoFactorVerifyDto): Promise<TokenPairDto> {
        return this.authService.verifyTwoFactor(dto.userId, dto.otp)
    }

    @Post('resend-otp')
    @HttpCode(HttpStatus.OK)
    async resendOtp(@Body() dto: {userId: string}) {
        return this.authService.resendOtp(dto.userId)
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refreshToken(@Body() dto: RefreshTokenDto) {
      return this.authService.refreshAccessToken(dto.refreshToken);
    }

    @Post('logout')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    async logout(@Req() req: any, @Body() body: {refreshToken?:string}){
        const userId = req.user.sub;
        const accessToken = this.extractToken(req);

        return this.authService.logout(
            userId,
            accessToken,
            body?.refreshToken
        );
    }

    @Post('logout-all')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    async logoutAll(@Request() req:any) {
        const userId = req.user.sub;
        return this.authService.logoutAll(userId)
    }

    @Get('get-profile')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    async getUserProfile(@Req() req: any) {
        const userId = req.user.sub; // Get userId from jwt token
        return this.authService.getUserProfile(userId)

    }

    @Post('update-profile')
    @UseGuards(JwtAuthGuard)
    @HttpCode(HttpStatus.OK)
    async updateUserProfile(@Req() req:any, @Body() dto: UpdateDto) {
        const userId = req.user.sub;
        return this.authService.updateUserProfile(userId, dto);
    }

    private extractToken(request:any): string {
        const [, token] = request.headers.authorization?.split(' ') ?? [];
        return token;
    }

}
