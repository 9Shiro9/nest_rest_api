import { ForbiddenException, Injectable } from "@nestjs/common";
import { User } from "@prisma/client";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from "argon2";
import { AuthDto } from "./dto";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
@Injectable({})
export class AuthService {
    constructor(private prisma : PrismaService,
        private jwt : JwtService ,
        private config : ConfigService
        ){}
    async signup(dto : AuthDto){
        try {
            const hash = await argon.hash(dto.password)
            const user = await this.prisma.user.create({
            data : {
                email : dto.email ,
                hash
            } 
        })
        return this.signToken(user.id , user.email)

        }
        catch(error) {
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code === "P2002"){
                    throw new ForbiddenException("Credentials Taken")
                }
            }
            throw error;
        }
    }
    async signin(dto : AuthDto){
        //find the email
        const user = await this.prisma.user.findUnique({
            where : {
                email : dto.email,
            }
        })

        //throw error if not found
        if(!user){
            throw new ForbiddenException("Credentials incorrect")
        }

        //compare password
        const pwMatches = await argon.verify(user.hash , dto.password);
        
        //throw error if incorrect
        if(!pwMatches){
            throw new ForbiddenException("Credentials incorrect");
        }

        return this.signToken(user.id , user.email)
    }

    async signToken(userId : number , email :string) :Promise<{access_token}> {
        const payload = {
            sub: userId ,
            email : email
        }
        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(payload , {
            expiresIn : "15m",
            secret : secret
        })
        return {
            access_token : token
        }
    }
}