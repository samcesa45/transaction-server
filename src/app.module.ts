import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { PrismaService } from './prisma/prisma.service';
import twiloConfig from './config/twilo.config';
import { ConfigModule } from '@nestjs/config';
import { TwiloModule } from './twilo/twilo.module';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { MailService } from './mail/mail.service';
import { MailModule } from './mail/mail.module';
import { RedisService } from './redis/redis.service';
import mailConfig from './config/mail.config';
import databaseConfig from './config/database.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load:[databaseConfig,twiloConfig,mailConfig]
    }),
    AuthModule,
    // TwiloModule,
    UsersModule,
    PrismaModule,
    MailModule
  ],
  controllers: [AppController],
  providers: [AppService, MailService, RedisService],
})
export class AppModule {}
