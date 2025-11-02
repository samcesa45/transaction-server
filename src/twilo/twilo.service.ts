import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import twilio from 'twilio';

@Injectable()
export class TwiloService {
    private readonly twilioClient: twilio.Twilio;
    private readonly twilioPhoneNumber: string;
    private readonly logger = new Logger(TwiloService.name);

    constructor(private config: ConfigService){
        const accountSid =  this.config.get<string>('twilio.twilioAccountSid');
        const authToken = this.config.get<string>('twilio.twilioAuthToken');
        this.twilioPhoneNumber = this.config.get<string>('twilio.twilioPhoneNumber')!

        if(!accountSid || !authToken || !this.twilioPhoneNumber) {
            this.logger.error('Twilio credentials not full configured in environment.')
        }

        this.twilioClient = twilio(accountSid,authToken)
    }

    async sendSms(to:string, body:string) : Promise<void> {
        try {
        if (!this.twilioPhoneNumber) {
            this.logger.warn(' No Twilio phone number configured. SMS not sent.');
            return;
            } 
        // In a production banking app, ensure 'to' numbers are in E.164 format
        await this.twilioClient.messages.create({
            body:body,
            from: this.twilioPhoneNumber,
            to: to
        });
        this.logger.log(`SMS sent to ${to} successfully.`)
        } catch (error) {
            this.logger.error(`Failed to send SMS to ${to}: ${error.message}`, error.stack)
            // fallback in dev mode
            if (process.env.NODE_ENV === 'development') {
                this.logger.warn(`🧪 Dev fallback OTP log to console: ${body}`);
            }
        }
    }

    async startVerification(to:string,channel:'sms' | 'call' | 'email') {
        const sid = this.config.get<string>('twilio.twilioVerifySid');
        return this.twilioClient.verify.v2.services(sid!)
        .verifications
        .create({to, channel})
    }

    async checkVerification(to:string, code: string) {
        return this.twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID!)
        .verificationChecks
        .create({to,code})
    }
}
