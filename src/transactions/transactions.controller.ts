import { Body, Controller, Get, HttpCode, HttpStatus, Post, Query, Req, UseGuards } from '@nestjs/common';
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
    async intrabankTransfer(@Body() dto: TransactionsDto, @Req() req:  RequestWithUser) {
       const transaction = await this.transactionsService.intrabankTransfer(
        dto,
        req.user.userId,
       );

       return {
        transactionId: transaction.id,
        reference: transaction.reference,
        amount: transaction.amount,
        status: transaction.status
       }
    }

    @Get()
    async getHistory(
        @Query('accountId') accountId: string,
        @Query('page') page: string = '1',
        @Query('limit') limit: string = '20'
    ) {
        return this.transactionsService.getTransactionHistory(
            accountId,
            parseInt(page),
            parseInt(limit),
        )
    }
}
