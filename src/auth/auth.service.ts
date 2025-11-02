import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt'
// import { TwiloService } from 'src/twilo/twilo.service';
import { RegisterDto, TokenPairDto, UpdateDto, UserLoginDto } from './dto/authdto';
import bcrypt from 'bcrypt'
import { MailService } from 'src/mail/mail.service';
import { RedisService } from 'src/redis/redis.service';
const saltRounds = parseInt(process.env.HASH_SALT_ROUNDS ?? '10',10);
const otpExpiryMins = parseInt(process.env.OTP_EXPIRY_MINUTES ?? '5', 10);

@Injectable()
export class AuthService {
    //token blacklist prefix for redis
    private readonly BLACKLIST_PREFIX = 'blacklist:token:';
    private readonly REFRESH_TOKEN_PREFIX = 'refresh:token:';

    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        // private twilioService: TwiloService,
        private mailService: MailService,
        // Add Redis for token blacklisting
        private redis: RedisService
    ){}

    async login(dto:UserLoginDto) {
        const user = await this.prisma.user.findUnique({where: {email: dto.email},
        select: {
            id: true,
            email: true,
            passwordHash: true,
            phoneNumber: true,
            isActive: true,
        }
        });

        if(!user) {
            throw new NotFoundException('No user found')
        }

        // Check if user account is active
        // if(!user.isActive) {
        //     throw new UnauthorizedException('Account is deactivated');
        // }

        const isMatch = await bcrypt.compare(dto.password, user.passwordHash);
        if(!isMatch) {
            throw new UnauthorizedException('Invalid credentials.')
        }

        if(!user.phoneNumber){
            throw new BadRequestException("Phone number required for 2FA setup.")
        }

        //2fa initiation
        const otp = this.generateOtp();
        const otpHash = await bcrypt.hash(otp, saltRounds);

        const expiry = new Date();
        expiry.setMinutes(expiry.getMinutes() + otpExpiryMins)

        // Store OTP state with transaction for atomicity
        await this.prisma.user.update({
            where: {id: user.id},
            data: {
                otpHash: otpHash,
                otpExpiresAt: expiry,
                lastLoginAttempt: new Date(), // Track login attempt
            }
        })

        // Send OTP via email (//Todo: will move to background job for better performance)
        //await this.twilioService.sendSms(user.phoneNumber,`Your 2FA code is: ${otp}. It expires in 5minutes.`)
          await this.mailService.sendOTPEmail(user.email,otp)

       return {
        message:'OTP sent. Verification required', 
        userId: user.id,  // Client needs userId to call the verification endpoint,
        expiresIn: otpExpiryMins * 60, 
       }
    }

    async verifyTwoFactor(userId: string, otp: string) {
        const user = await this.prisma.user.findUnique({where:{ id: userId },
        select: {
            id: true,
            otpHash: true,
            otpExpiresAt: true,
            isActive: true
        }
        });

        if(!user) {
            throw new UnauthorizedException('User not found');
        }

        // Allow login even if inactive (first time verification)
        // if(!user.isActive) {
        //     throw new UnauthorizedException('User not found or inactive');
        // }

        if(!user.otpHash || !user.otpExpiresAt) {
            throw new UnauthorizedException('NO OTP found. Please request a new one.');
        }
        if(user.otpExpiresAt < new Date()) {
            throw new UnauthorizedException('OTP expired. Please request a new one.');
        }

        const isOtpValid = await bcrypt.compare(otp, user.otpHash);
        if(!isOtpValid) {
            throw new UnauthorizedException('Invalid OTP.')
        }

        //clean up OTP state after successful verification
        await this.prisma.user.update({
            where: {id: userId},
            data: {
                otpHash:null,
                otpExpiresAt:null,
                lastLogin: new Date(),
                isActive: true
            }
        });

        //generate and return final tokens
        const tokens = await this.generateTokens(user.id)

        //store refresh token in Redis with expiry
        await this.storeRefreshToken(user.id, tokens.refreshToken);

        return tokens;
    }

    async generateTokens(userId: string): Promise<TokenPairDto> {
        const payload = {sub: userId};

        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync(payload, {
            expiresIn:'15m',
            secret: process.env.JWT_SECRET_KEY,
        }),
        this.jwtService.signAsync(payload, {
            expiresIn:'7d',
            secret: process.env.JWT_REFRESH_SECRET_KEY,
        })
    ]);

      return {accessToken, refreshToken}

    }

    /**
     *
     * Strategy: Token blacklisting with Redis
     */

    async logout(userId: string, accessToken: string, refreshToken?:string){
       try {
          //Decode tokens to get expiry times
          const accessPayload = this.jwtService.decode(accessToken);
          const accessTtl = accessPayload?.exp 
          ? Math.max(0, accessPayload.exp - Math.floor(Date.now() / 1000))
          : 900; //15mins fallback

          //Blacklisr access token (store until it would naturally expire)
          await this.redis.setex(
            `${this.BLACKLIST_PREFIX}${accessToken}`,
            accessTtl,
            'revoked'
          );

          //if refreshtoken provided , blacklist it too
          if(refreshToken) {
            const refreshPayload = this.jwtService.decode(refreshToken);
            const refreshTtl = refreshPayload?.exp 
            ? Math.max(0, refreshPayload.exp - Math.floor(Date.now() / 1000))
            : 604800// 7day fallback

            await this.redis.setex(
                `${this.BLACKLIST_PREFIX}${refreshToken}`,
                refreshTtl,
                'revoked'
            );

            //remove from active refresh tokens
            await this.redis.del(`${this.REFRESH_TOKEN_PREFIX}${userId}`)
          }
          this.prisma.user.update({
            where: {id: userId},
            data: {lastLogout: new Date()}
          }).catch(err => console.error('Failed to update logout time:', err));
          return {message: 'Logout successful'}
       } catch (error) {
          throw new BadRequestException('Logout failed')
       }
    }

    /**
     * 
     * Logout from all devices - invalidate all user's tokens
     */

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
                604800 //7 days (max refresh token life)
            );
            return {message: 'Logged out from all devices'}
        } catch (error) {
            throw new BadRequestException('Logout from all devices failed');
        }
    }

    /**
     * 
     * Check if token is blacklisted (call this in your AuthGuard)
     */
    async isTokenBlacklisted(token: string):Promise<boolean> {
        const result = await this.redis.get(`${this.BLACKLIST_PREFIX}${token}`);
        return result !== null;
    }

    /**
     * 
     * Check if user has logged out from all devices after token was issued
     */
    async hasLoggedOutAll(userId: string, tokenIssuedAt: number): Promise<boolean> {
        const logoutTimestamp = await this.redis.get(`logout:all:${userId}`);
        if(!logoutTimestamp) return false;

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
            refreshToken
        )
    }

    async refreshAccessToken(refreshToken: string): Promise<{accessToken: string;refreshToken:string}> {
        try {
            //verify refresh token
            const payload = await this.jwtService.verifyAsync(refreshToken, {
                secret: process.env.JWT_REFRESH_SECRET_KEY,
            });

            const userId = payload.sub;

            //check if token is blacklisted
            if (await this.isTokenBlacklisted(refreshToken)) {
                throw new UnauthorizedException('Token has been revoked');
            }

            //check if user logged out from all devices
            if ( await this.hasLoggedOutAll(userId, payload.iat)) {
                throw new UnauthorizedException('Session expired. Please login again.')
            }

            //verify if user still exists and is active
            const user = await this.prisma.user.findUnique({
                where: {id: userId},
                select: {id: true, isActive: true}
            });

            if (!user || !user.isActive) {
                throw new UnauthorizedException('User not found or inactive');
            }

            //Generate new access token
            const newAccessToken = await this.jwtService.signAsync(
                {sub: userId},
                {
                    expiresIn:'15m',
                    secret: process.env.JWT_SECRET_KEY,
                }
            );

            //Generate new refreshToken
            const newRefreshToken = await this.jwtService.signAsync(
                {sub: userId},
                {
                    expiresIn:'7d',
                    secret: process.env.JWT_REFRESH_SECRET_KEY,
                }
            )
            //Blacklist the old refresh token
            await this.redis.get(`${this.BLACKLIST_PREFIX}${refreshToken}`)

            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken
            }
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token')
        }
    }

    /**
     * 
     * Resend OTP for 2FA
     */
    async resendOtp(userId: string) {
        const user = await this.prisma.user.findUnique({
            where: {id: userId},
            select: {
                id: true,
                email: true,
                phoneNumber: true,
                lastLoginAttempt: true,
            }
        });
        
        if(!user) {
            throw new UnauthorizedException('User not found');
        }

        //Rate limiting: prevent OTP spam
        const now = new Date()
        if(user.lastLoginAttempt) {
           const timeSinceLastAttempt = now.getTime() - user.lastLoginAttempt.getTime();
           if (timeSinceLastAttempt < 60000) {//1 minute
              throw new BadRequestException(
                `Please wait ${Math.ceil((60000 - timeSinceLastAttempt) / 1000)} seconds before requesting a new OTP`
              )
           }
        }

        //Generate new OTP
        const otp = this.generateOtp();
        const otpHash = await bcrypt.hash(otp, saltRounds);

        const expiry = new Date();
        expiry.setMinutes(expiry.getMinutes() + otpExpiryMins);

        await this.prisma.user.update({
            where: {id: userId},
            data: {
                otpHash,
                otpExpiresAt: expiry,
                lastLoginAttempt: now
            }
        });

        await this.mailService.sendOTPEmail(user.email, otp);

        return {
            message: "New OTP sent",
            expiresIn: otpExpiryMins * 60,
        }
    }
    async register(dto: RegisterDto){
        //Check if user already exists
        const existingUser = await this.prisma.user.findUnique({
            where: {email: dto.email}
        });

        if (existingUser) {
            throw new BadRequestException("User with this email already exists");
        }

        //Hash password
        const passwordHash = await bcrypt.hash(dto.password,saltRounds);

        //create user
        const user = await this.prisma.user.create({
            data:{
                email: dto.email,
                passwordHash,
                firstName: dto.firstName,
                lastName: dto.lastName,
                middleName: dto.middleName,
                phoneNumber: dto.phoneNumber,
                isActive: false, //will be activated after 2fa verification
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true
            }
        });

        return {
            message:'User registered successfully',
            userId: user.id
        }
    }

    async getUserProfile (userId:string) {
        const user = await this.prisma.user.findUnique({where: {id: userId},
            select: {
                id:true,
                email: true,
                firstName: true,
                lastName:true,
                middleName:true,
                phoneNumber:true,
                isActive:true,
                lastLogin:true,
                createdAt:true
            }})
        if(!user) {
            throw new NotFoundException('No user found')
        }

      return user;

    }

    async updateUserProfile(userId:string,dto: UpdateDto) {
        const user = await this.prisma.user.findUnique({
            where: {id: userId}
        })

        if (!user) {
            throw new NotFoundException('User not found');
        }

        const updatedUser = await this.prisma.user.update({
            where: {id: userId},
            data: {
                firstName: dto.firstName,
                lastName: dto.lastName,
                middleName: dto.middleName,
                phoneNumber: dto.phoneNumber
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                middleName: true,
                phoneNumber: true,
                isActive: true,
                lastLogin: true,
                createdAt: true
            }
        });

        return updatedUser;
    }

    private generateOtp():string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
}
