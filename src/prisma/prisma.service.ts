import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    // Ensures the application connects to the database upon initialization
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
}
