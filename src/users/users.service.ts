import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService) {}

    async findOne(userId:string) {
        const user = await this.prisma.user.findUnique({
            where: {id:userId},
            select: {
                id:true,
                email:true,
                accounts:{
                   select:{accountNumber: true} 
                }
            }
        })

        if(!user) {
            throw new NotFoundException(`User with ID ${userId} not found.`)
        }
        return user;
    }
}
