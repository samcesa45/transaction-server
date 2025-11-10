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
import { TransactionsService } from './transactions/transactions.service';
import { TransactionsController } from './transactions/transactions.controller';
import { TransactionsModule } from './transactions/transactions.module';
import { BiometricService } from './biometric/biometric.service';
import { BiometricController } from './biometric/biometric.controller';
import { BiometricModule } from './biometric/biometric.module';
import { NotificationService } from './notification/notification.service';
import { FirebaseModule } from './firebase/firebase.module';
import { FirebaseService } from './firebase/firebase.service';
import { BankingGateway } from './bankinggateway/bankinggateway.gateway';
import { NotificationController } from './notification/notification.controller';
import { BankinggatewayController } from './bankinggateway/bankinggateway.controller';
import { BankinggatewayModule } from './bankinggateway/bankinggateway.module';
import mailConfig from './config/mail.config';
import databaseConfig from './config/database.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, twiloConfig, mailConfig],
    }),
    AuthModule,
    // TwiloModule,
    UsersModule,
    PrismaModule,
    MailModule,
    TransactionsModule,
    BiometricModule,
    FirebaseModule,
    BankinggatewayModule,
  ],
  controllers: [AppController, TransactionsController, BiometricController, NotificationController, BankinggatewayController],
  providers: [
    AppService,
    MailService,
    RedisService,
    TransactionsService,
    BiometricService,
    NotificationService,
    BankingGateway,
    FirebaseService,
  ],
})
export class AppModule {}
