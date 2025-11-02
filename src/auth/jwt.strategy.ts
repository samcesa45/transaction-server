import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from '@nestjs/passport';
import {Strategy, ExtractJwt} from 'passport-jwt'
import { PrismaService } from "src/prisma/prisma.service";
import { jwtConstants } from "./constants";

export type JwtPayload = {sub: string;email:string}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        private prisma: PrismaService
    ){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration:false,
            secretOrKey:jwtConstants.secret!
        });
    }

    async validate(payload: JwtPayload) {
        const user = await this.prisma.user.findUnique({where: {id: payload.sub},
        select: {
            id: true,
            email:true,
            isActive:true
        }})

        if(!user || !user.isActive) {
            throw new UnauthorizedException('User not found or inactive');
        }

        return {sub: user.id, email: user.email};
    }

}