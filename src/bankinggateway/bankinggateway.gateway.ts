import { UseGuards } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import {
  ConnectedSocket,
  MessageBody,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { jwtConstants } from 'src/auth/constants';
import { WsJwtGuard } from 'src/auth/ws-jwt.guard';
import { RedisService } from 'src/redis/redis.service';

@WebSocketGateway({
  cors: {
    origin: '*',
    credentials: true,
  },
  namespace: '/banking',
})
export class BankingGateway
  implements OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server: Server;

  private userSockets: Map<string, Set<string>> = new Map();

  constructor(
    private jwtService: JwtService,
    private redis: RedisService,
  ) {}

  async handleConnection(client: Socket) {
    try {
      //authenticate websocket connection
      const token =
        client.handshake.auth.token ||
        client.handshake.headers.authorization?.split(' ')[1];

      if (!token) {
        client.disconnect();
        return;
      }

      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtConstants.secret,
      });

      const userId = payload.sub;
      client.data.userId = userId;

      //track user's socket connections
      if (!this.userSockets.has(userId)) {
        this.userSockets.set(userId, new Set());
      }
      this.userSockets.get(userId)!.add(client.id);

      //join user's room
      client.join(`user:${userId}`);
      console.log(`User ${userId} connected via Websocket`);

      //send connection success
      client.emit('connected', { userId, message: 'Connected successfully',timestamp: new Date().toISOString() });
    } catch (error) {
      console.error('Websocket auth error:', error);
      client.disconnect();
    }
  }
  async handleDisconnect(client: Socket) {
    const userId = client.data.userId;

    if (userId && this.userSockets.has(userId)) {
      this.userSockets.get(userId)!.delete(client.id);

      if (this.userSockets.get(userId)!.size === 0) {
        this.userSockets.delete(userId);
      }
    }

    console.log(`Client disconnected: ${client.id}`);
  }

  @SubscribeMessage('subscribe_account')
  @UseGuards(WsJwtGuard)
  handleSubscribeAccount(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { accountId: string },
  ) {
    client.join(`account: ${data.accountId}`);
    return { event: 'subscribed', accountId: data.accountId };
  }

  /**
   * unsubscribe from account updates
   */
  @SubscribeMessage('unsubscribe_account')
  handleUnsubscribeAccount(
    @ConnectedSocket() client: Socket,
    @MessageBody() data: { accountId: string },
  ) {
    client.leave(`account: ${data.accountId}`);
    console.log(`Client unsubscribed from account: ${data.accountId}`);
    return { event: 'unsubscribed', accountId: data.accountId }
  }

  /**
   * Ping/pong for connection health check
   */
  @SubscribeMessage('ping')
  handlePing(@ConnectedSocket() client: Socket) {
    return { event:'pong', timestamp: new Date().toISOString()}
  }

  /**
   * Send transaction update to user
   */
  async sendTransactionUpdate(
    userId: string,
    transaction: {
      id: string;
      type: 'credit' | 'debit';
      amount: number;
      balance: number;
      reference: string;
      accountId: string;
      timestamp: Date;
    },
  ) {
    this.server.to(`user:${userId}`).emit('transaction',{
      ...transaction,
      timestamp: transaction.timestamp.toISOString()
    });

    this.server.to(`account:${transaction.accountId}`).emit('account_update', {
      accountId: transaction.accountId,
      balance: transaction.balance,
      lastTransaction: {
        id: transaction.id,
        type: transaction.type,
        amount: transaction.amount,
        reference: transaction.reference
      },
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send account balance update
   */
  async sendBalanceUpdate(accountId: string, balance: number) {
    this.server.to(`account:${accountId}`).emit('balance_update', {
      accountId,
      balance,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Send security alert to user
   */
  async sendSecurityAlert(
    userId: string,
    alert: { type: string; message: string },
  ) {
    this.server.to(`user:${userId}`).emit('security_alert', {
      ...alert,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Notify user to logout (e.g., account locked)
   */
  async forceLogout(userId: string, reason: string) {
    this.server.to(`user:${userId}`).emit('force_logout', { 
      reason, 
      timestamp: new Date().toISOString()
    });

    //disconnect all user's sockets
    const sockets = this.userSockets.get(userId);
    if (sockets) {
      sockets.forEach((socketId) => {
        const socket = this.server.sockets.sockets.get(socketId);
        socket?.disconnect();
      })
    }
  }

  /**
   * send transfer status update
   */
  sendTransferUpdate(
    userId: string,
    transfer: {
      id: string;
      status: 'pending' | 'completed' | 'failed';
      amount: number;
      recipient: string;
      message?: string;
    }
  )
  {
    console.log(`sending transfer update to user ${userId}`);

    this.server.to(`user:${userId}`).emit('transfer_update', {
      ...transfer,
      timestamp: new Date().toISOString()
    })
  }

  /**
   * broadcast system message to all connected clients
   */
  broadcastSystemMessage(message: string, type: 'info' | 'warning' | 'error') {
    console.log(`Broadcasting system message: ${message}`);

    this.server.emit('system_message', {
      message,
      type,
      timestamp: new Date().toISOString(),
    })
  }

  /**
   * get active connections count
   */

  getActiveConnectionCount(): number {
    return  this.server?.sockets?.sockets?.size;
  }

  /**
   * get users online count
   */
  getOnlineUsersCount(): number {
    return this.userSockets?.size;
  }

  /**
   * check if user is online
   */

  isUserOnline(userId: string): boolean {
    return this.userSockets.has(userId);
  }

  /**
   * send typing indicator (for support chat)
   */
  async sendTypingIndicator(userId: string, isTyping: boolean) {
    this.server.to(`user: ${userId}`).emit('typing', { isTyping });
  }
}
