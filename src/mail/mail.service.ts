import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private readonly transporter;
  private readonly from: string;
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get<string>('mail.host'),
      port: this.config.get<number>('mail.port'),
      secure: this.config.get<boolean>('mail.secure'),
      auth: {
        user: this.config.get<string>('mail.auth.user'),
        pass: this.config.get<string>('mail.auth.pass'),
      },
    });

    this.from = this.config.get<string>('mail.from') ?? 'no-reply@example.com';
  }

  async sendOTPEmail(to: string, otp: string): Promise<void> {
    try {
      await this.transporter.sendMail({
        from: this.from,
        to,
        subject: 'Your 2FA Verification Code.',
        text: `Your OTP code is: ${otp}. it expires in 5 minutes.`,
        html: `<h2>Your OTP Code</h2>
                     <p><b>${otp}</b></p>
                     <p>This code expires in 5 minutes.</p>
              
              `,
      });
      this.logger.log(`OTP email sent to ${to}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}: ${error.message}`);
    }
  }
}
