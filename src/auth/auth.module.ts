import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { PassportModule } from '@nestjs/passport';
import { PrismaModule } from 'src/prisma/prisma.module';
import { TwiloService } from 'src/twilo/twilo.service';
import { MailModule } from 'src/mail/mail.module';
import { RedisService } from 'src/redis/redis.service';

@Module({
    imports:[
        PassportModule,
        PrismaModule,
        MailModule,
        JwtModule.register({
            secret: process.env.JWT_SECRET_KEY,
            signOptions:{expiresIn:'15m'}
        })
    ],
    controllers:[AuthController],
    providers:[AuthService,JwtStrategy,TwiloService,RedisService],
    exports:[AuthService,JwtModule]

})
export class AuthModule {}
