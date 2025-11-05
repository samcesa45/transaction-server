import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { UsersService } from './users.service';
import type { RequestWithUser } from 'src/common';

@Controller('users')
export class UsersController {
    constructor( private readonly userService: UsersService){}
   
    @UseGuards(JwtAuthGuard)
    @Get('me')
    async getProfile(@Req() req: RequestWithUser) {
       // If the request reaches this line, the token is VALID, 
        // and the user data is available in req.user
        
       const userProfile = await this.userService.findOne(req.user.userId);
       return userProfile;
  
    }
}
