import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Request,
  UseGuards,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { UsersService } from './users.service';
import { UserDto } from './dto/userdto';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Get('get-profile')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async getUserProfile(@Request() req: any) {
    const userId = req.user.sub
    return this.userService.getUserProfile(userId);
  }

  @Post('update-profile')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async updateUserProfile(@Request() req: any, @Body() dto: UserDto) {
    const userId = req.user.sub;
    return this.userService.updateUserProfile(userId, dto);
  }
}
