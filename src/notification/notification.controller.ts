import { Body, Controller, Post, Request, UseGuards } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';

@Controller('notification')
export class NotificationController {
    constructor(private notificationService:NotificationService){}

    @Post('test')
    @UseGuards(JwtAuthGuard)
    async sendTestNotification(
    @Request() req,
    @Body() body: {title: string;body: string; data?:Record<string, string>}
    ) {
        await this.notificationService.sendNotification(
            req.user.sub,
            body.title,
            body.body,
            body.data
        );
        return {
            message: "Notification sent"
        }
    }
}
