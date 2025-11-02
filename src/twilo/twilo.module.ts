import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TwiloService } from './twilo.service';

@Module({
    imports:[ConfigModule],
    providers: [TwiloService],
    exports: [TwiloService]
})
export class TwiloModule {}
