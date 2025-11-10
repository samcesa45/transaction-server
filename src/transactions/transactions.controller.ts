import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { TransactionsService } from './transactions.service';
import { TransactionsDto } from './dto/transactionsdto';
import type { RequestWithUser } from 'src/common';

@UseGuards(JwtAuthGuard)
@Controller('transactions')
export class TransactionsController {
  constructor(private readonly transactionsService: TransactionsService) {}

  @Post('transfer/intrabank')
  @HttpCode(HttpStatus.CREATED)
  async intrabankTransfer(
    @Body() dto: TransactionsDto,
    @Req() req: RequestWithUser,
  ) {
    return this.transactionsService.intrabankTransfer(dto, req.user.userId);
  }

  @Get('/lookup/:accountNumber')
  @UseGuards(JwtAuthGuard)
  async lookupAccount(@Param('accountNumber') accountNumber: string) {
    return this.transactionsService.lookupAccount(accountNumber);
  }

  @Get()
  async getHistory(
    @Query('accountId') accountId: string,
    @Query('page') page: string = '1',
    @Query('limit') limit: string = '20',
  ) {
    return this.transactionsService.getTransactionHistory(
      accountId,
      parseInt(page),
      parseInt(limit),
    );
  }
}
