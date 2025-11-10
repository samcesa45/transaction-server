import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { jwtConstants } from './constants';

@Injectable()
export class WsJwtGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const client = context.switchToWs().getClient();
      const token = client.handshake.auth.token;

      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtConstants.secret,
      });

      client.data.userId = payload.sub;
      return true;
    } catch (error) {
      return false;
    }
  }
}
