import { Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { BankingGateway } from './bankinggateway.gateway';
import { WsJwtGuard } from 'src/auth/ws-jwt.guard';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';

@Controller('websocket')
export class BankinggatewayController {
    constructor(private bankingGateway: BankingGateway) {}

    @Post('test-transaction')
    @UseGuards(JwtAuthGuard)
    async testTransaction(@Request() req) {
        const userId = req.user.sub;

        this.bankingGateway.sendTransactionUpdate(userId, {
            id: 'test-' + Date.now(),
            type: 'credit',
            amount: 50000,
            balance: 150000,
            reference: 'Test Transaction',
            accountId:'test-account',
            timestamp: new Date()
        });

        return {
            message: 'Test transaction sent via Websockets'
        }
    }

    @Post('test-security-alert')
    @UseGuards(JwtAuthGuard)
    async testSecurityAlert(@Request() req) {
        const userId = req.user.sub;

        this.bankingGateway.sendSecurityAlert(userId, {
            type: 'login',
            message:'New login from unknown device'
        })
    }

    @Get('stats')
    @UseGuards(JwtAuthGuard)
    getStats() {
        return {
            activeConnections: this.bankingGateway.getActiveConnectionCount(),
            onlineUsers: this.bankingGateway.getOnlineUsersCount()
        }
    }

}
