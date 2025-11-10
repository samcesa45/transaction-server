import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { BiometricController } from './biometric.controller';
import { BiometricService } from './biometric.service';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from 'src/prisma/prisma.module';
import { MailModule } from 'src/mail/mail.module';
import { RedisService } from 'src/redis/redis.service';
import { JwtStrategy } from 'src/auth/jwt.strategy';

@Module({
  imports: [
    PassportModule,
    PrismaModule,
    MailModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET_KEY,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  controllers: [BiometricController],
  providers: [BiometricService, JwtStrategy, RedisService],
  exports: [BiometricService, JwtModule],
})
export class BiometricModule {}
