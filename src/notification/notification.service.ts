import { Injectable } from '@nestjs/common';
import { FirebaseService } from 'src/firebase/firebase.service';
import { PrismaService } from 'src/prisma/prisma.service';
import * as admin from 'firebase-admin';

@Injectable()
export class NotificationService {
  constructor(
    private prisma: PrismaService,
    private firebaseService: FirebaseService,
  ) {}

  /**
   * Send push notification to user's device(s)
   */
  async sendNotification(
    userId: string,
    title: string,
    body: string,
    data?: Record<string, string>,
    deviceId?: string,
  ): Promise<void> {
    try {
      //Get user's devices with FCM tokens
      const devices = await this.prisma.device.findMany({
        where: {
          userId,
          isActive: true,
          fcmToken: { not: null },
          ...(deviceId && { deviceId }),
        },
        select: { fcmToken: true, deviceId: true },
      });

      if (devices.length === 0) {
        console.log(`No FCM tokens for user ${userId}`);
        return;
      }

      const tokens = devices
        .map((d) => d.fcmToken)
        .filter((token): token is string => !!token);

      //send to multiple devices
      const message: admin.messaging.MulticastMessage = {
        tokens,
        notification: {
          title,
          body,
        },
        data: data || {},
        android: {
          priority: 'high' as const,
          notification: {
            sound: 'default',
            channelId: 'banking_notifications',
            priority:'high' as const
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              badge: 1,
              alert: {
                title,
                body,
              }
            },
          },
          headers: {
            'apns-priority': '10'
          }
        },
      };
      const messaging = this.firebaseService.getMessage();
      const response = await messaging.sendEachForMulticast(message);
       
      console.log(`Successfully sent: ${response.successCount}`);
      console.log(`Failed: ${response.failureCount}`);

      //Handle failed tokens
      if (response.failureCount > 0) {
        const failedTokens: string[] = [];

        response.responses.forEach((resp, idx) => {
          if (!resp.success) {
            console.log(`Failed to send to ${tokens[idx]}:`, resp.error);

            //remove invalid tokens (expired, unregistered)
            if ( resp.error?.code === 'messaging/invalid-registration-token' || 
              resp.error?.code === 'messaging/registration-token-not-registered'
            )
            failedTokens.push(tokens[idx]);
          }
        });

        //clean up invalid tokens
        if(failedTokens.length > 0) {
          await this.prisma.device.updateMany({
            where: { fcmToken: { in: failedTokens }},
            data: { fcmToken: null }
          });
          console.log(`Removed ${failedTokens.length} invalid tokens(s)`)
        }
      }
    } catch (error) {
      console.error('Push notification error:', error);
    }
  }
  /**
   * Send transaction notification
   */
  async notifyTransaction(
    userId: string,
    type: 'credit' | 'debit',
    amount: number,
    balance: number,
    reference: string,
  ): Promise<void> {
    const title = type === 'credit' ? 'Credit Alert' : 'Debit Alert';
    const body = `₦${amount.toLocaleString()} ${type === 'credit' ? 'received' : 'sent'}. Balance: ₦${balance.toLocaleString()}`;

    await this.sendNotification(userId, title, body, {
      type: 'transaction',
      transactionType: type,
      amount: amount.toString(),
      balance: balance.toString(),
      reference,
    });
  }

  /**
   * Send login notification
   */
  async notifyLogin(
    userId: string,
    deviceName: string,
    location?: string,
  ): Promise<void> {
    const title = 'New Login';
    const body = `Login detected on ${deviceName}${location ? `from ${location}` : ''}`;

    await this.sendNotification(userId, title, body, {
      type: 'security',
      action: 'login',
      deviceName
    });
  }

  /**
   * send security alert
   */

  async notifySecurityAlert(userId: string, message: string): Promise<void> {
    await this.sendNotification(userId, '⚠️ Security Alert', message, {
      type: 'security_alert',
    });
  }

  /**
   * send account locked notification
   */
  async notifyAccountLocked(userId: string): Promise<void> {
    await this.sendNotification(userId, 'Account Locked',
      'Your account has been locked due to multiple failed login attempts. Please reset your password',
      {type: 'account_locked'}
    )
  }

  /**
   * send transfer notification
   */
  async notifyTransferInitiated(userId: string, amount: number, recipient: string): Promise<void> {
    await this.sendNotification(
      userId, 'transfer initiated',
      `₦${amount.toLocaleString()} transfer to ${recipient} is been processed.`,
      {
        type: 'transfer',
        amount: amount.toString()
      }
    )
  }
}
